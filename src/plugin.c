/*
 * Plugin GoldHEN (.prx): Script Hook untuk GTA V PS4, hanya story mode.
 *
 * Cara kerja:
 *  1. Thread init menunggu sampai game selesai mendaftarkan native (tabel terisi).
 *  2. Handler native GET_GAME_TIMER di tabel diganti wrapper kita (hanya menulis data,
 *     tidak ada patch kode). Script game memanggilnya hampir tiap frame, jadi wrapper
 *     jalan di thread script game dengan konteks yang benar.
 *  3. Tiap kali nilai timer berubah, wrapper menjalankan satu tick Lua.
 *
 * Asumsi yang HARUS dibuktikan di console (lihat README, bagian "Belum terbukti"):
 *  - Script game me-resolve handler dari tabel SETELAH plugin memasang hook.
 *  - plugin_load dipanggil GoldHEN (dikonfirmasi dari main.c plugin contoh, build #3).
 */
#include "offsets.h"
#include "platform.h"
#include "shv_core.h"
#include "shv_lua.h"

#include <stdio.h>

#if defined(__has_include)
# if __has_include(<plugin_common.h>)
#  include <plugin_common.h>
# endif
#endif
#ifndef attr_public
# define attr_public __attribute__((visibility("default")))
#endif
#ifndef attr_module_hidden
# define attr_module_hidden
#endif

static shv_native_fn g_orig_timer;
static volatile int  g_busy;
static volatile int  g_lua_ready;
static volatile uint32_t g_ticks;
static uint32_t      g_last_timer;
static uint32_t      g_last_frame = 0xFFFFFFFFu;
static int           g_frame_ok = 1;      /* 0 kalau GET_FRAME_COUNT tidak bisa dipanggil */

static void core_log(const char *m) { plat_log(m); }

static void timer_wrapper(shv_ctx *ctx)
{
    uint32_t t;
    g_orig_timer(ctx);                       /* hasil asli ditulis ke ctx->ret */
    if (!ctx->ret) return;
    t = (uint32_t)*(int32_t *)ctx->ret;
    if (t == g_last_timer) return;           /* timer harus berubah */
    if (g_frame_ok) {                        /* satu tick per FRAME, bukan per panggilan timer */
        uint64_t fr[8];
        if (shv_call(H_GET_FRAME_COUNT, NULL, 0, fr) != 0) { g_frame_ok = 0; plat_log("GET_FRAME_COUNT tidak tersedia; tick per perubahan timer"); }
        else {
            uint32_t fc = (uint32_t)fr[0];
            if (fc == g_last_frame) return;
            g_last_frame = fc;
        }
    }
    if (__sync_lock_test_and_set(&g_busy, 1)) return; /* cegah masuk ulang / thread lain */
    g_last_timer = t;
    if (!g_lua_ready) {
        g_lua_ready = (shv_lua_init() == 0);
        if (!g_lua_ready) plat_log("shv_lua_init gagal; script tidak jalan");
    }
    if (g_lua_ready) { shv_lua_tick(t); g_ticks++; }
    __sync_lock_release(&g_busy);
}

/* Pilih hash GET_GAME_TIMER. Build lama: hash kanonik. Build 1.57: hash berbeda, jadi pilih lewat PERILAKU:
 * handler getter variabel global yang naik ~1 ms per ms nyata. Bentuk kode saja tidak cukup unik. */
static uint64_t pick_timer_hash(void)
{
    static shv_timer_cand c[1024];
    static uint32_t v0[1024];
    int nA = 0, nB = 0, n, pass = 0;
    uint64_t guess = shv_xlate(H_GET_GAME_TIMER), best = 0;
    char line[160];

    if (shv_has_native(H_GET_GAME_TIMER)) return H_GET_GAME_TIMER;
    n = shv_find_timer_candidates(c, 1024, &nA, &nB);
    snprintf(line, sizeof line, "timer: %d kandidat bentuk (A=%d B=%d), tebakan crossmap=0x%llx", n, nA, nB,
             (unsigned long long)guess);
    plat_log(line);
    for (int i = 0; i < n; i++) v0[i] = *(volatile uint32_t *)c[i].counter;
    plat_sleep_ms(500);
    for (int i = 0; i < n; i++) {
        uint32_t d = *(volatile uint32_t *)c[i].counter - v0[i];
        if (d >= 350 && d <= 1500) {
            pass++;
            snprintf(line, sizeof line, "timer: lolos uji perilaku hash=0x%llx delta=%u%s",
                     (unsigned long long)c[i].hash, d, c[i].hash == guess ? " (= tebakan crossmap)" : "");
            plat_log(line);
            if (!best || c[i].hash == guess) best = c[i].hash;
        }
    }
    snprintf(line, sizeof line, "timer: %d lolos uji perilaku, dipakai 0x%llx", pass, (unsigned long long)best);
    plat_log(line);
    return best;
}

static void *init_thread(void *arg)
{
    unsigned waited_ms = 0;
    int hooked = 0;
    int core_ok = 0;
    char line[96];
    (void)arg;

    plat_log("=== scripthook start (CUSA00419; layout v2 build 1.57 + v1 cadangan) ===");
    if (!plat_log_ok())
        plat_notify("Scripthook: log tidak bisa ditulis ke\n/data/GoldHEN/scripthook\nCoded by Said Awali");
    {
        uintptr_t base = 0; size_t tsize = 0;
        plat_main_module(&base, &tsize);
        core_ok = (shv_core_init_auto(base, tsize, core_log) == 0);
        if (!core_ok) plat_diag(base, tsize);
    }
    if (!core_ok) {
        char msg[400];
        plat_log("berhenti: layout game tidak ditemukan. Lihat docs/ANALISIS.md dan README.");
        /* diagnosis ikut ditampilkan di layar karena log belum tentu bisa ditulis */
        snprintf(msg, sizeof msg, "Scripthook tidak cocok dengan versi game ini\n%s\nCoded by Said Awali",
                 shv_last_diag());
        plat_notify(msg);
        return NULL;
    }

    /* Tabel native diisi saat init engine. Tunggu sampai terisi, lalu pilih native timer. */
    {
        uint64_t th = 0;
        while (waited_ms < 180000) {
            if (shv_native_count() >= 3000 || shv_has_native(H_GET_GAME_TIMER)) {
                plat_sleep_ms(1500);                 /* beri waktu registrasi selesai */
                th = pick_timer_hash();
                if (th && shv_hook_native(th, timer_wrapper, &g_orig_timer) == 0) { hooked = 1; break; }
            }
            plat_sleep_ms(1000);
            waited_ms += 1000;
        }
    }
    if (!hooked) {
        plat_log("berhenti: native timer tidak ditemukan / tidak bisa di-hook dalam 180 detik");
        plat_notify("Scripthook gagal dimuat\nLihat scripthook.log\nCoded by Said Awali");
        return NULL;
    }
    snprintf(line, sizeof line, "hook dipasang setelah %u ms menunggu", waited_ms);
    plat_log(line);
    plat_notify("Scripthook aktif\nCoded by Said Awali");

    /* Pengawas: beri tahu di log kalau hook terpasang tapi tidak pernah dipanggil. */
    for (unsigned s = 0; s < 120; s++) {
        plat_sleep_ms(1000);
        if (g_ticks > 0) { plat_log("tick aktif: script mulai berjalan"); return NULL; }
    }
    plat_log("PERINGATAN: hook terpasang tapi 120 detik tanpa tick. Kemungkinan script game sudah "
             "men-cache handler lama. Lihat README bagian 'Belum terbukti' langkah 2.");
    return NULL;
}

/* Metadata yang dibaca GoldHEN (sama seperti plugin contoh di GoldHEN_Plugins_Repository). */
attr_public const char *g_pluginName = "scripthook";
attr_public const char *g_pluginDesc = "Script Hook (Lua) untuk GTA V PS4, story mode";
attr_public const char *g_pluginAuth = "Said Awali";
attr_public unsigned int g_pluginVersion = 0x00000100; /* 1.00 */

/* Titik masuk sebenarnya: GoldHEN memanggil plugin_load saat plugin dimuat di proses game.
 * module_start/module_stop di plugin contoh hanya "return 0", jadi dibuat sama. */
int attr_public plugin_load(int argc, const char *argv[])
{
    (void)argc; (void)argv;
    return plat_start_thread(init_thread, NULL) == 0 ? 0 : -1;
}

int attr_public plugin_unload(int argc, const char *argv[])
{
    (void)argc; (void)argv;
    shv_unhook_all();
    shv_lua_shutdown();
    return 0;
}

int attr_module_hidden module_start(long argc, const void *args)
{
    (void)argc; (void)args;
    return 0;
}

int attr_module_hidden module_stop(long argc, const void *args)
{
    (void)argc; (void)args;
    return 0;
}
