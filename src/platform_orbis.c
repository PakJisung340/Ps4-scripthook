/*
 * Lapisan platform PS4 (OpenOrbis + GoldHEN Plugin SDK).
 *
 * PERHATIAN: file ini BELUM dikompilasi atau diuji. Saya tidak punya OpenOrbis
 * di sesi tempat ini dibuat, dan dokumentasi GoldHEN untuk signature
 * module_start serta API hook tidak sempat terbaca. Fungsi di bawah memakai
 * nama API libkernel standar (scePthreadCreate, sceKernelUsleep) dan libc.
 * Kalau compiler protes, sesuaikan di sini saja; file lain tidak bergantung SDK.
 */
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Header OpenOrbis v0.5.4 tidak mendeklarasikan tipe ScePthread (build #2 gagal di sini),
 * jadi dua fungsi libkernel dideklarasikan sendiri dengan nama lokal; __asm__ menjaga
 * nama simbol aslinya untuk linker. Nama lokal berbeda mencegah konflik dengan header.
 */
extern int shv_pthread_create(void **thread, const void *attr, void *(*entry)(void *),
                              void *arg, const char *name) __asm__("scePthreadCreate");
extern int shv_usleep(unsigned int usec) __asm__("sceKernelUsleep");

/*
 * Base eboot. Pada PS4 retail, modul utama (eboot.bin) umumnya dimuat di 0x400000
 * (dipakai juga oleh cheat GoldHEN: "eboot.bin + offset"). Kalau base di console
 * kamu beda, taruh angkanya (misalnya 0x400000) di SHV_DIR/base.txt.
 * Signature byte dicek di shv_core_init, jadi base yang salah akan ditolak
 * dengan pesan di log, bukan dipakai diam-diam.
 */
uintptr_t plat_main_module_base(void)
{
    char *buf = NULL; size_t len = 0;
    uintptr_t base = 0x400000;
    if (plat_read_file(SHV_DIR "/base.txt", &buf, &len) == 0) {
        unsigned long long v = strtoull(buf, NULL, 0);
        if (v) base = (uintptr_t)v;
        free(buf);
    }
    return base;
}

int plat_start_thread(void *(*fn)(void *), void *arg)
{
    void *t = NULL; /* ScePthread adalah pointer ke struct thread */
    return shv_pthread_create(&t, NULL, fn, arg, "shv_init") == 0 ? 0 : -1;
}

void plat_sleep_ms(unsigned ms)
{
    shv_usleep(ms * 1000u);
}

void plat_log(const char *msg)
{
    FILE *f = fopen(SHV_DIR "/scripthook.log", "a");
    if (!f) return;
    fputs(msg, f);
    fputc('\n', f);
    fclose(f);
}

int plat_read_file(const char *path, char **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *b;
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0 || n > (8 * 1024 * 1024)) { fclose(f); return -1; }
    b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return -1; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return -1; }
    b[n] = 0;
    fclose(f);
    *buf = b;
    if (len) *len = (size_t)n;
    return 0;
}
