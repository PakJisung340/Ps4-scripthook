/*
 * Offset untuk GTA V PS4, eboot.bin hasil dump pengguna.
 *   SHA-256: 5d149d0229ed79d02e84c84a123b836d1cdb9866c3872615cb278dbded2690cc
 *   Ukuran : 47.992.667 byte, ELF x86-64 FreeBSD (sudah didekripsi)
 *   Title ID yang dikenali di dalamnya: CUSA00411, CUSA00419, CUSA00880
 *
 * Semua alamat di bawah adalah VA di dalam ELF (di-link di base 0), jadi alamat
 * runtime = base eboot + nilai ini. Semuanya diturunkan dari analisis statis
 * (disassembly objdump), BELUM diuji di console. Lihat docs/ANALISIS.md.
 */
#ifndef SHV_OFFSETS_H
#define SHV_OFFSETS_H

#define SHV_EBOOT_SHA256 "5d149d0229ed79d02e84c84a123b836d1cdb9866c3872615cb278dbded2690cc"

/* Fungsi RegisterNative(hash=rdi, handler=rsi). Dipanggil 4.790 kali saat init engine. */
#define OFF_REGISTER_NATIVE   0x1AB0840ULL

/* Array 256 pointer ke node (indeks = byte rendah hash), di BSS. Dibaca oleh
 * RegisterNative (0x1AB0840) dan fungsi lain di 0x1AB08B0 (kemungkinan lookup). */
#define OFF_NATIVE_BUCKETS    0x3244A28ULL

/* Handler GET_GAME_TIMER. Dipakai hanya untuk pengecekan versi (signature). */
#define OFF_GET_GAME_TIMER_HANDLER 0x915FB0ULL

/* 14 byte pertama RegisterNative: push rbp; mov rbp,rsp; push r15; push r14;
 * push r13; push r12; push rbx; push rax; mov r14,rsi; mov r15,rdi (20 byte). */
#define SIG_REGISTER_NATIVE_LEN 20
#define SIG_REGISTER_NATIVE \
  { 0x55,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50,0x49,0x89,0xF6,0x49,0x89,0xFF }

/* mov rax,[rdi]; lea rcx,[rip+...] */
#define SIG_GET_GAME_TIMER_LEN 6
#define SIG_GET_GAME_TIMER { 0x48,0x8B,0x07,0x48,0x8D,0x0D }

/* Hash native (64-bit, sama seperti di PC). Semuanya ada di tabel data/natives_ps4_cusa00419.csv */
#define H_GET_GAME_TIMER   0x9CD27B0045628463ULL
#define H_PLAYER_PED_ID    0xD80958FC74E988A6ULL
#define H_GET_ENTITY_COORDS 0x3FEF770D40960D5AULL
#define H_GET_FRAME_COUNT   0xFC8202EFC642E6F2ULL   /* untuk satu tick per frame */

#endif
