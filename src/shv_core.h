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

#endif
