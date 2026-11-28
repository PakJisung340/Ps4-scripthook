/*
 * Inti Script Hook untuk GTA V PS4: baca tabel native milik game, panggil native,
 * dan ganti handler satu native (untuk dapat "tick" per frame).
 *
 * Kode ini portabel (tidak butuh SDK PS4) supaya logikanya bisa diuji di host.
 */
#ifndef SHV_CORE_H
#define SHV_CORE_H

#include <stdint.h>
#include <stddef.h>

typedef void (*shv_log_fn)(const char *msg);

/* Tata letak sama dengan scrNativeCallContext di PC. Yang terverifikasi dari
 * disassembly handler PS4: ret di +0x00 dan args di +0x10. */
typedef struct shv_ctx {
    uint64_t *ret;        /* +0x00 buffer return */
    uint32_t  argc;       /* +0x08 jumlah argumen */
    uint32_t  _pad0;
    uint64_t *args;       /* +0x10 array slot 8-byte */
    uint32_t  data_count; /* +0x18 */
    uint32_t  _pad1;
    uint64_t  scratch[64];
} shv_ctx;

typedef void (*shv_native_fn)(shv_ctx *ctx);

/* base = alamat load eboot. verify=1 memeriksa signature byte dulu dan menolak
 * kalau versi eboot tidak cocok. Return 0 kalau sukses. */
int shv_core_init(uintptr_t base, int verify, shv_log_fn log);

/* Seperti shv_core_init, tetapi kalau offset statis tidak cocok, cari layout lewat pola kode
 * di segmen kode [base, base+text_size). Return 0 sukses. */
int shv_core_init_auto(uintptr_t base, size_t text_size, shv_log_fn log);
uintptr_t shv_buckets_addr(void);

/* Cek apakah [addr, addr+len) terpetakan dan bisa dibaca (dipasok platform; aman dari crash). */
typedef int (*shv_readable_fn)(uintptr_t addr, size_t len);

/* Cari tabel native lewat BENTUK datanya (bukan hash atau kode): array 256 pointer di segmen data
 * yang menunjuk ke node dengan handler di segmen kode dan hash[0]&0xFF == nomor bucket.
 * Dipakai kalau build game memakai hash yang berbeda dari yang dianalisis. Return 0 sukses. */
int shv_core_init_structural(uintptr_t tbase, size_t tsize, uintptr_t dbase, size_t dsize,
                             shv_readable_fn rd, shv_log_fn log);

/* Hash kanonik (nativedb) -> hash build 1.57; 0 kalau tidak dikenal. */
uint64_t shv_xlate(uint64_t canon);

/* Jumlah native yang terdaftar di tabel saat ini (0 kalau tabel belum terisi). */
int shv_native_count(void);

/* 1 kalau hash terdaftar di tabel. */
int shv_has_native(uint64_t hash);

/* Kandidat "GET_GAME_TIMER" untuk build berhash lain: handler yang hanya mengembalikan satu u32 dari
 * variabel global. counter = alamat variabel itu. nA/nB = jumlah kecocokan tiap bentuk kode. */
typedef struct { uint64_t hash; uintptr_t counter; } shv_timer_cand;
int shv_find_timer_candidates(shv_timer_cand *out, int max, int *nA, int *nB);

/* Tulis seluruh tabel (hash, handler relatif ke base, 16 byte awal handler) per baris ke sink. */
void shv_dump_natives(shv_log_fn sink);
uintptr_t shv_register_native_addr(void);

/* Ringkasan diagnosis (base + byte asli) dari shv_core_init yang gagal; untuk notifikasi. */
const char *shv_last_diag(void);

/* Handler asli (belum di-hook) untuk hash, atau NULL kalau belum terdaftar. */
shv_native_fn shv_find_handler(uint64_t hash);

/* Ganti handler 'hash' dengan 'wrapper'. Handler asli disimpan di *orig.
 * Return 0 sukses, -1 kalau hash belum terdaftar, -2 kalau slot hook penuh. */
int shv_hook_native(uint64_t hash, shv_native_fn wrapper, shv_native_fn *orig);

/* Kembalikan semua handler yang di-hook ke aslinya. */
void shv_unhook_all(void);

/* Panggil native. ret harus menunjuk ke minimal 8 slot uint64_t (boleh NULL).
 * Return 0 sukses, -1 native tidak ada. Hook dilewati (selalu handler asli). */
int shv_call(uint64_t hash, const uint64_t *args, uint32_t argc, uint64_t *ret);

/* Panggil handler lewat VA eboot (alamat dari natives.lua). Return -1 kalau VA di luar segmen kode. */
int shv_call_addr(uint64_t va, const uint64_t *args, uint32_t argc, uint64_t *ret);

/* Panggil handler lewat VA (relatif ke base eboot), gaya Velora.invoke. Hanya alamat yang terdaftar di tabel native
 * yang diterima; return -1 kalau bukan. */
int shv_call_va(uint64_t va, const uint64_t *args, uint32_t argc, uint64_t *ret);

#endif
