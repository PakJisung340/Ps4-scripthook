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
        if (bad) return -1;
    }
    logf_("core siap, base=0x%llx tabel=0x%llx", base, base + OFF_NATIVE_BUCKETS);
    return 0;
}

/* Cari slot (node,indeks) untuk hash. */
static int find_slot(uint64_t hash, shv_node **node_out, uint32_t *idx_out)
{
    shv_node **buckets = (shv_node **)(g_base + OFF_NATIVE_BUCKETS);
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
