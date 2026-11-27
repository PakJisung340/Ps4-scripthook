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

static void core_log(const char *m) { plat_log(m); }

static void timer_wrapper(shv_ctx *ctx)
{
    uint32_t t;
    g_orig_timer(ctx);                       /* hasil asli ditulis ke ctx->ret */
    if (!ctx->ret) return;
    t = (uint32_t)*(int32_t *)ctx->ret;
    if (t == g_last_timer) return;           /* satu tick per perubahan timer */
    if (__sync_lock_test_and_set(&g_busy, 1)) return; /* cegah masuk ulang / thread lain */
    g_last_timer = t;
    if (!g_lua_ready) {
        g_lua_ready = (shv_lua_init() == 0);
        if (!g_lua_ready) plat_log("shv_lua_init gagal; script tidak jalan");
    }
    if (g_lua_ready) { shv_lua_tick(t); g_ticks++; }
    __sync_lock_release(&g_busy);
}

static void *init_thread(void *arg)
{
    unsigned waited_ms = 0;
    int hooked = 0;
    char line[96];
    (void)arg;

    plat_log("=== scripthook start (CUSA00419 build, eboot " SHV_EBOOT_SHA256 ") ===");
    if (shv_core_init(plat_main_module_base(), 1, core_log) != 0) {
        plat_log("berhenti: signature/base tidak cocok. Lihat docs/ANALISIS.md dan README.");
        plat_notify("Scripthook tidak cocok dengan versi game ini\nLihat scripthook.log\nCoded by Said Awali");
        return NULL;
    }

    /* Tabel native diisi saat init engine. Tunggu sampai GET_GAME_TIMER terdaftar. */
    while (waited_ms < 180000) {
        if (shv_hook_native(H_GET_GAME_TIMER, timer_wrapper, &g_orig_timer) == 0) { hooked = 1; break; }
        plat_sleep_ms(1);
        waited_ms++;
    }
    if (!hooked) {
        plat_log("berhenti: GET_GAME_TIMER tidak pernah terdaftar dalam 180 detik");
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
