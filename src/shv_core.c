#include "shv_core.h"
#include "offsets.h"

#include <stdio.h>
#include <string.h>

/* Node tabel native. Tata letak dari disassembly RegisterNative (0x1AB0840):
 *   +0x00 next, +0x08..+0x38 7 handler, +0x40 count, +0x48..+0x78 7 hash (total 0x80). */
typedef struct shv_node {
    struct shv_node *next;
    shv_native_fn    handler[7];
    uint32_t         count;
    uint32_t         _pad;
    uint64_t         hash[7];
} shv_node;

_Static_assert(sizeof(shv_node) == 0x80, "node harus 0x80 byte");
_Static_assert(offsetof(shv_node, handler) == 0x08, "handler di +0x08");
_Static_assert(offsetof(shv_node, count) == 0x40, "count di +0x40");
_Static_assert(offsetof(shv_node, hash) == 0x48, "hash di +0x48");
_Static_assert(offsetof(shv_ctx, args) == 0x10, "args di +0x10");
_Static_assert(offsetof(shv_ctx, argc) == 0x08, "argc di +0x08");

#define MAX_HOOKS 4

static uintptr_t   g_base;
static uintptr_t   g_buckets;   /* alamat array 256 bucket (dari offset statis atau hasil pemindaian) */
static uintptr_t   g_reg;       /* alamat RegisterNative */
static shv_log_fn  g_log;
static struct { uint64_t hash; shv_native_fn orig; shv_native_fn wrapper; } g_hooks[MAX_HOOKS];
static int g_nhooks;

static void logf_(const char *fmt, uint64_t a, uint64_t b)
{
    char buf[160];
    if (!g_log) return;
    snprintf(buf, sizeof buf, fmt, (unsigned long long)a, (unsigned long long)b);
    g_log(buf);
}

static char g_diag[200];

const char *shv_last_diag(void) { return g_diag; }

/* Cetak n byte dalam hex ke log, untuk membandingkan signature yang diharapkan dan yang ada. */
static void log_bytes(const char *label, const uint8_t *p, size_t n)
{
    char buf[200];
    size_t pos = 0;
    if (!g_log) return;
    pos += (size_t)snprintf(buf, sizeof buf, "%s:", label);
    for (size_t i = 0; i < n && pos + 4 < sizeof buf; i++)
        pos += (size_t)snprintf(buf + pos, sizeof buf - pos, " %02x", p[i]);
    g_log(buf);
}

int shv_core_init(uintptr_t base, int verify, shv_log_fn log)
{
    g_base = base;
    g_buckets = base + OFF_NATIVE_BUCKETS;
    g_reg = base + OFF_REGISTER_NATIVE;
    g_log = log;
    g_nhooks = 0;

    if (verify) {
        static const uint8_t sig_reg[SIG_REGISTER_NATIVE_LEN] = SIG_REGISTER_NATIVE;
        static const uint8_t sig_tmr[SIG_GET_GAME_TIMER_LEN] = SIG_GET_GAME_TIMER;
        int bad = 0;
        if (memcmp((const void *)(base + OFF_REGISTER_NATIVE), sig_reg, sizeof sig_reg) != 0) {
            logf_("signature RegisterNative tidak cocok di base 0x%llx (+0x%llx)", base, OFF_REGISTER_NATIVE);
            log_bytes("  seharusnya", sig_reg, sizeof sig_reg);
            log_bytes("  yang ada  ", (const uint8_t *)(base + OFF_REGISTER_NATIVE), sizeof sig_reg);
            bad = 1;
        }
        if (memcmp((const void *)(base + OFF_GET_GAME_TIMER_HANDLER), sig_tmr, sizeof sig_tmr) != 0) {
            logf_("signature GET_GAME_TIMER tidak cocok di base 0x%llx (+0x%llx)", base, OFF_GET_GAME_TIMER_HANDLER);
            log_bytes("  seharusnya", sig_tmr, sizeof sig_tmr);
            log_bytes("  yang ada  ", (const uint8_t *)(base + OFF_GET_GAME_TIMER_HANDLER), sizeof sig_tmr);
            bad = 1;
        }
        if (bad) {
            const uint8_t *r = (const uint8_t *)(base + OFF_REGISTER_NATIVE);
            const uint8_t *t = (const uint8_t *)(base + OFF_GET_GAME_TIMER_HANDLER);
            snprintf(g_diag, sizeof g_diag,
                     "base=0x%llx\nRN: %02x %02x %02x %02x %02x %02x %02x %02x\nGT: %02x %02x %02x %02x %02x %02x",
                     (unsigned long long)base, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
                     t[0], t[1], t[2], t[3], t[4], t[5]);
            return -1;
        }
    }
    logf_("core siap, base=0x%llx tabel=0x%llx", base, base + OFF_NATIVE_BUCKETS);
    return 0;
}

/* Cari slot (node,indeks) untuk hash. */
static int find_slot(uint64_t hash, shv_node **node_out, uint32_t *idx_out)
{
    shv_node **buckets = (shv_node **)g_buckets;
    shv_node *n = buckets[hash & 0xFF];
    int guard = 0;
    while (n && guard++ < 4096) {
        uint32_t cnt = n->count > 7 ? 7 : n->count;
        for (uint32_t i = 0; i < cnt; i++) {
            if (n->hash[i] == hash) {
                *node_out = n;
                *idx_out = i;
                return 1;
            }
        }
        n = n->next;
    }
    return 0;
}

static shv_native_fn original_for(uint64_t hash, shv_native_fn current)
{
    for (int i = 0; i < g_nhooks; i++)
        if (g_hooks[i].hash == hash) return g_hooks[i].orig;
    return current;
}

shv_native_fn shv_find_handler(uint64_t hash)
{
    shv_node *n; uint32_t i;
    if (!find_slot(hash, &n, &i)) return NULL;
    return original_for(hash, n->handler[i]);
}

int shv_hook_native(uint64_t hash, shv_native_fn wrapper, shv_native_fn *orig)
{
    shv_node *n; uint32_t i;
    if (g_nhooks >= MAX_HOOKS) return -2;
    if (!find_slot(hash, &n, &i)) return -1;
    for (int k = 0; k < g_nhooks; k++)
        if (g_hooks[k].hash == hash) return -2; /* sudah di-hook */

    g_hooks[g_nhooks].hash = hash;
    g_hooks[g_nhooks].orig = n->handler[i];
    g_hooks[g_nhooks].wrapper = wrapper;
    if (orig) *orig = n->handler[i];
    g_nhooks++;
    n->handler[i] = wrapper;   /* tulis 8 byte ter-align, data saja: tidak menyentuh kode */
    logf_("hook terpasang untuk native 0x%llx (handler asli 0x%llx)", hash, (uint64_t)(uintptr_t)g_hooks[g_nhooks - 1].orig);
    return 0;
}

void shv_unhook_all(void)
{
    for (int k = 0; k < g_nhooks; k++) {
        shv_node *n; uint32_t i;
        if (find_slot(g_hooks[k].hash, &n, &i) && n->handler[i] == g_hooks[k].wrapper)
            n->handler[i] = g_hooks[k].orig;
    }
    g_nhooks = 0;
}

int shv_call(uint64_t hash, const uint64_t *args, uint32_t argc, uint64_t *ret)
{
    shv_native_fn fn = shv_find_handler(hash);
    uint64_t argbuf[32];
    uint64_t retbuf[8];
    shv_ctx ctx;

    if (!fn) return -1;
    if (argc > 32) argc = 32;
    memset(argbuf, 0, sizeof argbuf);
    memset(retbuf, 0, sizeof retbuf);
    memset(&ctx, 0, sizeof ctx);
    if (args && argc) memcpy(argbuf, args, argc * sizeof(uint64_t));

    ctx.ret = retbuf;
    ctx.args = argbuf;
    ctx.argc = argc;
    fn(&ctx);

    if (ret) memcpy(ret, retbuf, sizeof retbuf);
    return 0;
}

/* ------------------------------------------------------------------------------------------
 * Pencarian layout saat runtime (untuk build game yang beda dari eboot yang dianalisis).
 *
 * Log console menunjukkan build yang jalan tidak identik dengan eboot yang dianalisis (ukuran
 * segmen kode beda, byte di offset statis bukan awal RegisterNative). Pola pendaftaran native
 * sama di semua build:
 *     lea rsi,[rip+handler] ; movabs rdi,<hash> ; call RegisterNative
 * Dari pendaftaran GET_GAME_TIMER kita dapat alamat handler dan RegisterNative, lalu
 * "lea r12,[rip+disp]" di dalam RegisterNative memberi alamat array bucket.
 * Hanya memindai segmen kode modul utama (R-X), jadi aman dibaca.
 * ------------------------------------------------------------------------------------------ */
static int locate_by_scan(uintptr_t base, size_t text_size)
{
    const uint8_t *t = (const uint8_t *)base;
    const uint64_t h = H_GET_GAME_TIMER;
    uint8_t pat[8];
    static const uint8_t sig_tmr[SIG_GET_GAME_TIMER_LEN] = SIG_GET_GAME_TIMER;
    int hits = 0, shaped = 0;

    memcpy(pat, &h, 8);
    for (size_t i = 9; i + 13 <= text_size; i++) {
        const uint8_t *q = (const uint8_t *)memchr(t + i, pat[0], text_size - 13 - i + 1);
        int32_t d_lea, d_call;
        uintptr_t handler, reg, bucket = 0;
        int found_lea = 0;

        if (!q) break;
        i = (size_t)(q - t);
        if (memcmp(q, pat, 8) != 0) continue;
        hits++;
        if (!(q[-2] == 0x48 && q[-1] == 0xBF && q[-9] == 0x48 && q[-8] == 0x8D && q[-7] == 0x35 && q[8] == 0xE8))
            continue;
        shaped++;
        memcpy(&d_lea, q - 6, 4);
        memcpy(&d_call, q + 9, 4);
        handler = (uintptr_t)((intptr_t)(q - 2) + d_lea);
        reg = (uintptr_t)((intptr_t)(q + 13) + d_call);
        if (handler < base || handler + sizeof sig_tmr > base + text_size) continue;
        if (reg < base || reg + 0x80 > base + text_size) continue;
        if (memcmp((const void *)handler, sig_tmr, sizeof sig_tmr) != 0) continue;   /* handler harus GET_GAME_TIMER */
        if (memcmp((const void *)reg, "\x55\x48\x89\xE5", 4) != 0) continue;          /* prolog push rbp; mov rbp,rsp */

        for (size_t j = 0; j < 0x60; j++) {
            const uint8_t *c = (const uint8_t *)reg + j;
            if (c[0] == 0x4C && c[1] == 0x8D && c[2] == 0x25) {                       /* lea r12,[rip+disp32] */
                int32_t d; memcpy(&d, c + 3, 4);
                bucket = (uintptr_t)((intptr_t)(c + 7) + d);
                found_lea = 1;
                break;
            }
        }
        if (!found_lea) continue;
        if (bucket >= base && bucket < base + text_size) continue;                     /* tabel ada di data, bukan di kode */

        g_reg = reg;
        g_buckets = bucket;
        logf_("layout ditemukan lewat pemindaian: RegisterNative=base+0x%llx tabel=base+0x%llx",
              (uint64_t)(reg - base), (uint64_t)(bucket - base));
        logf_("  (offset statis analisis: RegisterNative=+0x%llx tabel=+0x%llx)",
              (uint64_t)OFF_REGISTER_NATIVE, (uint64_t)OFF_NATIVE_BUCKETS);
        return 0;
    }
    snprintf(g_diag, sizeof g_diag, "scan gagal: hit=%d berpola=%d\nbase=0x%llx size=0x%llx",
             hits, shaped, (unsigned long long)base, (unsigned long long)text_size);
    logf_("pemindaian gagal: hit hash=%llu berpola=%llu", (uint64_t)hits, (uint64_t)shaped);
    return -1;
}

int shv_core_init_auto(uintptr_t base, size_t text_size, shv_log_fn log)
{
    /* 1. coba offset statis (build yang sama dengan eboot analisis) */
    if (OFF_REGISTER_NATIVE + SIG_REGISTER_NATIVE_LEN <= text_size &&
        OFF_GET_GAME_TIMER_HANDLER + SIG_GET_GAME_TIMER_LEN <= text_size &&
        shv_core_init(base, 1, log) == 0) {
        logf_("offset statis cocok (build sama dengan eboot analisis), tabel=base+0x%llx", OFF_NATIVE_BUCKETS, 0);
        return 0;
    }
    /* 2. cari lewat pola kode */
    g_base = base;
    g_log = log;
    g_nhooks = 0;
    logf_("offset statis tidak cocok; memindai segmen kode (base=0x%llx size=0x%llx)", base, (uint64_t)text_size);
    return locate_by_scan(base, text_size);
}

uintptr_t shv_buckets_addr(void) { return g_buckets; }
uintptr_t shv_register_native_addr(void) { return g_reg; }
