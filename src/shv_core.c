#include "shv_core.h"
#include "offsets.h"
#include "crossmap157.h"

#include <stdio.h>
#include <stdlib.h>
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
static int g_v2;               /* 1 = tabel ter-enkripsi (build 1.57), 0 = tata letak lama */

/* Akses node yang tidak peduli tata letak.
 * v2 (dari disassembly RegisterNative build 1.57 di VA 0x25A1B70): node 0x100 byte.
 *   +0x00 next  : 2x u32, di-XOR dengan (u32)node dan kunci di +0x08
 *   +0x10+8*i   : handler (polos)
 *   +0x48/+0x4C : count = [+4C] ^ (u32)(node+0x48) ^ [+48]
 *   +0x54+16*i  : hash i = {lo,hi,kunci}; lo = [s]^(u32)s^[s+8], hi = [s+4]^(u32)s^[s+8], s = alamat slot */
static inline uint32_t rd32(uintptr_t a) { return *(const volatile uint32_t *)a; }
static void *n_next(void *n)
{
    uintptr_t p = (uintptr_t)n;
    if (!g_v2) return ((shv_node *)n)->next;
    {
        uint32_t k = (uint32_t)p ^ rd32(p + 8);
        uint64_t lo = rd32(p) ^ k, hi = rd32(p + 4) ^ k;
        return (void *)(uintptr_t)(lo | (hi << 32));
    }
}
static uint32_t n_count(void *n)
{
    uintptr_t p = (uintptr_t)n;
    uint32_t c;
    if (!g_v2) c = ((shv_node *)n)->count;
    else c = rd32(p + 0x4C) ^ (uint32_t)(p + 0x48) ^ rd32(p + 0x48);
    return c > 7 ? 7 : c;
}
static uint64_t n_hash(void *n, uint32_t i)
{
    if (!g_v2) return ((shv_node *)n)->hash[i];
    {
        uintptr_t s = (uintptr_t)n + 0x54 + 16 * (uintptr_t)i;
        uint32_t k = (uint32_t)s ^ rd32(s + 8);
        return (uint64_t)(rd32(s) ^ k) | ((uint64_t)(rd32(s + 4) ^ k) << 32);
    }
}
static shv_native_fn *n_hslot(void *n, uint32_t i)
{
    if (!g_v2) return &((shv_node *)n)->handler[i];
    return (shv_native_fn *)((uintptr_t)n + 0x10 + 8 * (uintptr_t)i);
}

static void logf_(const char *fmt, uint64_t a, uint64_t b)
{
    char buf[160];
    if (!g_log) return;
    snprintf(buf, sizeof buf, fmt, (unsigned long long)a, (unsigned long long)b);
    g_log(buf);
}

static uintptr_t g_tlo, g_thi;   /* segmen kode modul utama */
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
    g_v2 = 0;
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
    void *n = buckets[hash & 0xFF];
    int guard = 0;
    while (n && guard++ < 4096) {
        uint32_t cnt = n_count(n);
        for (uint32_t i = 0; i < cnt; i++) {
            if (n_hash(n, i) == hash) {
                *node_out = (shv_node *)n;
                *idx_out = i;
                return 1;
            }
        }
        n = n_next(n);
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
    return original_for(hash, *n_hslot(n, i));
}

int shv_hook_native(uint64_t hash, shv_native_fn wrapper, shv_native_fn *orig)
{
    shv_node *n; uint32_t i;
    if (g_nhooks >= MAX_HOOKS) return -2;
    if (!find_slot(hash, &n, &i)) return -1;
    for (int k = 0; k < g_nhooks; k++)
        if (g_hooks[k].hash == hash) return -2; /* sudah di-hook */

    g_hooks[g_nhooks].hash = hash;
    g_hooks[g_nhooks].orig = *n_hslot(n, i);
    g_hooks[g_nhooks].wrapper = wrapper;
    if (orig) *orig = *n_hslot(n, i);
    g_nhooks++;
    *n_hslot(n, i) = wrapper;   /* tulis 8 byte ter-align, data saja: tidak menyentuh kode */
    logf_("hook terpasang untuk native 0x%llx (handler asli 0x%llx)", hash, (uint64_t)(uintptr_t)g_hooks[g_nhooks - 1].orig);
    return 0;
}

void shv_unhook_all(void)
{
    for (int k = 0; k < g_nhooks; k++) {
        shv_node *n; uint32_t i;
        if (find_slot(g_hooks[k].hash, &n, &i) && *n_hslot(n, i) == g_hooks[k].wrapper)
            *n_hslot(n, i) = g_hooks[k].orig;
    }
    g_nhooks = 0;
}

uint64_t shv_xlate(uint64_t canon)
{
    unsigned lo = 0, hi = shv_xtab_n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (shv_xtab[mid].canon < canon) lo = mid + 1; else hi = mid;
    }
    return (lo < shv_xtab_n && shv_xtab[lo].canon == canon) ? shv_xtab[lo].build : 0;
}

static void do_call(shv_native_fn fn, const uint64_t *args, uint32_t argc, uint64_t *ret)
{
    uint64_t argbuf[32];
    uint64_t retbuf[8];
    shv_ctx ctx;
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
}

int shv_call(uint64_t hash, const uint64_t *args, uint32_t argc, uint64_t *ret)
{
    shv_native_fn fn = shv_find_handler(hash);
    if (!fn && g_v2) {                       /* build 1.57: script memakai hash kanonik */
        uint64_t b = shv_xlate(hash);
        if (b) fn = shv_find_handler(b);
    }
    if (!fn) return -1;
    do_call(fn, args, argc, ret);
    return 0;
}

/* Himpunan alamat handler asli yang terdaftar (untuk memvalidasi pemanggilan lewat alamat, gaya Velora). */
static uintptr_t *g_hset;
static unsigned g_hset_n;

static int cmp_uptr(const void *a, const void *b)
{
    uintptr_t x = *(const uintptr_t *)a, y = *(const uintptr_t *)b;
    return x < y ? -1 : x > y;
}

static void build_hset(void)
{
    shv_node **bk = (shv_node **)g_buckets;
    unsigned cap = (unsigned)shv_native_count() + 16, n = 0;
    uintptr_t *set = (uintptr_t *)malloc(cap * sizeof *set);
    if (!set) return;
    for (int bi = 0; bi < 256; bi++) {
        void *nd = bk[bi];
        int guard = 0;
        while (nd && guard++ < 4096) {
            uint32_t c = n_count(nd);
            for (uint32_t i = 0; i < c && n < cap; i++)
                set[n++] = (uintptr_t)original_for(n_hash(nd, i), *n_hslot(nd, i));
            nd = n_next(nd);
        }
    }
    qsort(set, n, sizeof *set, cmp_uptr);
    g_hset = set; g_hset_n = n;
}

int shv_call_va(uint64_t va, const uint64_t *args, uint32_t argc, uint64_t *ret)
{
    uintptr_t target = g_base + (uintptr_t)va;
    unsigned lo = 0, hi;
    if (!g_buckets) return -1;
    if (!g_hset) build_hset();
    hi = g_hset_n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (g_hset[mid] < target) lo = mid + 1; else hi = mid;
    }
    if (lo >= g_hset_n || g_hset[lo] != target) return -1;   /* bukan handler native terdaftar */
    do_call((shv_native_fn)target, args, argc, ret);
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

/* Jumlah native yang terbaca dari tabel (v2 ter-enkripsi atau v1). */
int shv_native_count(void)
{
    shv_node **bk = (shv_node **)g_buckets;
    int total = 0;
    if (!g_buckets) return 0;
    for (int bi = 0; bi < 256; bi++) {
        void *n = bk[bi];
        int guard = 0;
        while (n && guard++ < 4096) { total += (int)n_count(n); n = n_next(n); }
    }
    return total;
}

/* Build 1.57 (eboot f9161cc5...): thunk RegisterNative di VA 0x1E175B0 memuat "lea rdi,[rip+..]" ke
 * objek tabel di VA 0x3DF7680. Byte awal thunk dipakai sebagai cek identitas build. */
#define V2_OFF_THUNK   0x1E175B0ULL
#define V2_OFF_BUCKETS 0x3DF7680ULL
static int init_v2(uintptr_t base, size_t text_size, shv_log_fn log)
{
    static const uint8_t sig[9] = { 0x48,0x89,0xF0,0x48,0x89,0xF9,0x48,0x8D,0x3D };
    if (V2_OFF_THUNK + sizeof sig > text_size) return -1;
    if (memcmp((const void *)(base + V2_OFF_THUNK), sig, sizeof sig) != 0) {
        logf_("v2: thunk RegisterNative tidak cocok di +0x%llx", V2_OFF_THUNK, 0);
        log_bytes("  yang ada", (const uint8_t *)(base + V2_OFF_THUNK), sizeof sig);
        return -1;
    }
    g_base = base; g_log = log; g_nhooks = 0;
    g_tlo = base; g_thi = base + text_size;
    g_v2 = 1;
    g_reg = base + V2_OFF_THUNK;
    g_buckets = base + V2_OFF_BUCKETS;
    logf_("tata letak v2 (build 1.57, tabel ter-enkripsi): tabel=base+0x%llx", V2_OFF_BUCKETS, 0);
    return 0;
}

int shv_core_init_auto(uintptr_t base, size_t text_size, shv_log_fn log)
{
    /* 0. build 1.57 (tabel ter-enkripsi) */
    g_log = log;
    if (init_v2(base, text_size, log) == 0) return 0;
    g_v2 = 0;
    g_tlo = base; g_thi = base + text_size;
    /* 1. coba offset statis (build yang sama dengan eboot analisis) */
    if (OFF_REGISTER_NATIVE + SIG_REGISTER_NATIVE_LEN <= text_size &&
        OFF_GET_GAME_TIMER_HANDLER + SIG_GET_GAME_TIMER_LEN <= text_size &&
        shv_core_init(base, 1, log) == 0) {
        logf_("offset statis cocok (build sama dengan eboot analisis), tabel=base+0x%llx", OFF_NATIVE_BUCKETS, 0);
        return 0;
    }
    /* 2. cari lewat pola kode */
    g_tlo = base; g_thi = base + text_size;
    g_base = base;
    g_log = log;
    g_nhooks = 0;
    logf_("offset statis tidak cocok; memindai segmen kode (base=0x%llx size=0x%llx)", base, (uint64_t)text_size);
    return locate_by_scan(base, text_size);
}

/* ------------------------------------------------------------------------------------------
 * Pencarian lewat bentuk data (tidak bergantung hash maupun pola kode pendaftaran).
 * ------------------------------------------------------------------------------------------ */
static int node_ok(uintptr_t addr, unsigned bucket, shv_readable_fn rd)
{
    const shv_node *n = (const shv_node *)addr;
    uintptr_t h;
    if (addr & 7) return 0;
    if (!rd(addr, sizeof *n)) return 0;
    if (n->count < 1 || n->count > 7) return 0;
    if ((unsigned)(n->hash[0] & 0xFF) != bucket) return 0;
    h = (uintptr_t)n->handler[0];
    return h >= g_tlo && h < g_thi;
}

int shv_core_init_structural(uintptr_t tbase, size_t tsize, uintptr_t dbase, size_t dsize,
                             shv_readable_fn rd, shv_log_fn log)
{
    int shown = 0, cands = 0;
    g_log = log; g_base = tbase; g_tlo = tbase; g_thi = tbase + tsize; g_nhooks = 0;
    if (!rd || dsize < 2048 || !rd(dbase, dsize)) {
        logf_("pencarian bentuk: segmen data 0x%llx (+0x%llx) tidak terbaca", dbase, (uint64_t)dsize);
        snprintf(g_diag, sizeof g_diag, "data seg tak terbaca\nbase=0x%llx", (unsigned long long)dbase);
        return -1;
    }
    for (uintptr_t p = (dbase + 7) & ~(uintptr_t)7; p + 2048 <= dbase + dsize; p += 8) {
        const uint64_t *e = (const uint64_t *)p;
        int miss = 0, bad = 0;
        for (int i = 0; i < 256 && miss <= 56; i++) {
            uint64_t v = e[i];
            if (v == 0 || (v & 7) || v < 0x10000 || v >> 47) miss++;
        }
        if (miss > 56) continue;
        cands++;
        for (int i = 0; i < 256 && bad <= 8; i++)
            if (e[i] && !node_ok((uintptr_t)e[i], (unsigned)i, rd)) bad++;
        if (bad <= 8) {
            g_buckets = p;
            logf_("tabel ditemukan lewat bentuk data: array bucket di 0x%llx (data+0x%llx)", p, (uint64_t)(p - dbase));
            return 0;
        }
        if (shown < 3) {                       /* tata letak node mungkin beda: simpan contoh untuk diagnosis */
            for (int i = 0; i < 256; i++) {
                if (e[i] && rd((uintptr_t)e[i], 0x80)) {
                    char lab[48];
                    snprintf(lab, sizeof lab, "kandidat 0x%llx node[%d]", (unsigned long long)p, i);
                    log_bytes(lab, (const uint8_t *)(uintptr_t)e[i], 0x40);
                    break;
                }
            }
            shown++;
        }
    }
    snprintf(g_diag, sizeof g_diag, "bentuk gagal: kandidat=%d\ndata=0x%llx+0x%llx",
             cands, (unsigned long long)dbase, (unsigned long long)dsize);
    logf_("pencarian bentuk gagal: kandidat array=%llu", (uint64_t)cands, 0);
    return -1;
}

int shv_has_native(uint64_t hash)
{
    shv_node *n; uint32_t i;
    return g_buckets && find_slot(hash, &n, &i);
}

int shv_find_timer_candidates(shv_timer_cand *out, int max, int *nA, int *nB)
{
    int cnt = 0, a = 0, b = 0;
    shv_node **bk = (shv_node **)g_buckets;
    if (!g_buckets || !g_thi) return 0;
    for (int bi = 0; bi < 256; bi++) {
        void *n = bk[bi];
        int guard = 0;
        while (n && guard++ < 4096) {
            uint32_t c = n_count(n);
            for (uint32_t i = 0; i < c; i++) {
                const uint8_t *h = (const uint8_t *)(uintptr_t)*n_hslot(n, i);
                uintptr_t target = 0;
                int32_t d;
                if ((uintptr_t)h < g_tlo || (uintptr_t)h + 16 > g_thi) continue;
                /* A: mov rax,[rdi]; lea rcx,[rip+d]; mov ecx,[rcx]; mov [rax],ecx; ret */
                if (!memcmp(h, "\x48\x8B\x07\x48\x8D\x0D", 6) && !memcmp(h + 10, "\x8B\x09\x89\x08\xC3", 5)) {
                    memcpy(&d, h + 6, 4); target = (uintptr_t)((intptr_t)(h + 10) + d); a++;
                }
                /* B: mov rax,[rdi]; mov ecx,[rip+d]; mov [rax],ecx; ret */
                else if (!memcmp(h, "\x48\x8B\x07\x8B\x0D", 5) && !memcmp(h + 9, "\x89\x08\xC3", 3)) {
                    memcpy(&d, h + 5, 4); target = (uintptr_t)((intptr_t)(h + 9) + d); b++;
                }
                if (target && cnt < max) { out[cnt].hash = n_hash(n, i); out[cnt].counter = target; cnt++; }
            }
            n = n_next(n);
        }
    }
    if (nA) *nA = a;
    if (nB) *nB = b;
    return cnt;
}

void shv_dump_natives(shv_log_fn sink)
{
    shv_node **bk = (shv_node **)g_buckets;
    char line[200];
    if (!g_buckets || !sink) return;
    for (int bi = 0; bi < 256; bi++) {
        void *n = bk[bi];
        int guard = 0;
        while (n && guard++ < 4096) {
            uint32_t c = n_count(n);
            for (uint32_t i = 0; i < c; i++) {
                uintptr_t h = (uintptr_t)*n_hslot(n, i);
                size_t pos = (size_t)snprintf(line, sizeof line, "%016llx %llx",
                                              (unsigned long long)n_hash(n, i),
                                              (unsigned long long)(h - g_tlo));
                if (h >= g_tlo && h + 16 <= g_thi)
                    for (int k = 0; k < 16; k++)
                        pos += (size_t)snprintf(line + pos, sizeof line - pos, " %02x", ((const uint8_t *)h)[k]);
                sink(line);
            }
            n = n_next(n);
        }
    }
}

uintptr_t shv_buckets_addr(void) { return g_buckets; }
uintptr_t shv_register_native_addr(void) { return g_reg; }
