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
 * Header OpenOrbis memetakan errno ke __errno_location(), tetapi libSceLibcInternal
 * (yang ditautkan Makefile kerangka GoldHEN) tidak mengekspornya: build #4 gagal di tahap
 * link hanya karena simbol ini, dipakai oleh lauxlib.c (luaL_fileresult dkk., tidak kita pakai).
 * Sediakan sendiri; hidden supaya tidak keluar sebagai ekspor modul.
 */
static int g_shv_errno;
__attribute__((visibility("hidden"))) int *__errno_location(void)
{
    return &g_shv_errno;
}

/*
 * Base eboot. Pada PS4 retail, modul utama (eboot.bin) umumnya dimuat di 0x400000
 * (dipakai juga oleh cheat GoldHEN: "eboot.bin + offset"). Kalau base di console
 * kamu beda, taruh angkanya (misalnya 0x400000) di SHV_DIR/base.txt.
 * Signature byte dicek di shv_core_init, jadi base yang salah akan ditolak
 * dengan pesan di log, bukan dipakai diam-diam.
 */
/*
 * Daftar modul proses (libkernel). Tata letak SceKernelModuleInfo dari kode homebrew PS4
 * (ukuran total 0x160 byte). BELUM diuji di console; kalau hasilnya gagal, jatuh ke 0x400000
 * dan semua modul yang terbaca dicatat di scripthook.log untuk diagnosis.
 */
extern int shv_get_module_list(int *handles, size_t num, size_t *actual) __asm__("sceKernelGetModuleList");
extern int shv_get_module_info(int handle, void *info) __asm__("sceKernelGetModuleInfo");

typedef struct { void *address; unsigned int size; int prot; } shv_modseg;
typedef struct {
    size_t size;
    char name[256];
    shv_modseg seg[4];
    unsigned int seg_count;
    unsigned char fingerprint[20];
} shv_modinfo;

uintptr_t plat_main_module_base(void)
{
    char *buf = NULL; size_t len = 0;
    uintptr_t base = 0, first_base = 0;
    int handles[256];
    size_t n = 0;
    char line[256];

    /* 1. override manual */
    if (plat_read_file(SHV_DIR "/base.txt", &buf, &len) == 0) {
        unsigned long long v = strtoull(buf, NULL, 0);
        free(buf);
        if (v) {
            snprintf(line, sizeof line, "base dari base.txt: 0x%llx", v);
            plat_log(line);
            return (uintptr_t)v;
        }
    }

    /* 2. tanya sistem: modul bernama eboot */
    memset(handles, 0, sizeof handles);
    if (shv_get_module_list(handles, 256, &n) == 0) {
        for (size_t i = 0; i < n && i < 256; i++) {
            shv_modinfo mi;
            memset(&mi, 0, sizeof mi);
            mi.size = sizeof mi;
            if (shv_get_module_info(handles[i], &mi) != 0) continue;
            mi.name[sizeof mi.name - 1] = 0;
            snprintf(line, sizeof line, "modul[%u] handle=%d nama=%s seg0=0x%llx size=0x%x segmen=%u",
                     (unsigned)i, handles[i], mi.name, (unsigned long long)(uintptr_t)mi.seg[0].address,
                     mi.seg[0].size, mi.seg_count);
            plat_log(line);
            if (!first_base) first_base = (uintptr_t)mi.seg[0].address;
            if (!base && strstr(mi.name, "eboot")) base = (uintptr_t)mi.seg[0].address;
        }
    } else {
        plat_log("sceKernelGetModuleList gagal");
    }

    if (!base) base = first_base;     /* modul pertama = executable utama */
    if (!base) { plat_log("base tidak terbaca dari sistem, memakai 0x400000"); base = 0x400000; }
    snprintf(line, sizeof line, "base dipakai: 0x%llx", (unsigned long long)base);
    plat_log(line);
    return base;
}

/*
 * Notifikasi layar lewat sceKernelSendNotificationRequest (libkernel). Tata letak struct
 * diambil dari kode homebrew PS4 yang umum dipakai, BELUM diuji di console ini; kalau salah,
 * paling buruk notifikasi tidak muncul. URI ikon sama dengan TEX_ICON_SYSTEM di
 * plugin_common.h milik GoldHEN.
 */
extern int shv_send_notification(int device, void *req, size_t size, int blocking)
    __asm__("sceKernelSendNotificationRequest");

typedef struct {
    int type, reqId, priority, msgId, targetId, userId, unk1, unk2, appId, errorNum, unk3;
    unsigned char useIconImageUri;
    char message[1024];
    char iconImageUri[1024];
    char unk[1024];
} shv_notify_req;

void plat_notify(const char *msg)
{
    shv_notify_req req;
    memset(&req, 0, sizeof req);
    req.type = 0;
    req.targetId = -1;
    req.useIconImageUri = 1;
    snprintf(req.message, sizeof req.message, "%s", msg);
    snprintf(req.iconImageUri, sizeof req.iconImageUri, "%s", "cxml://psnotification/tex_icon_system");
    shv_send_notification(0, &req, sizeof req, 0);
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

/*
 * fopen tidak membuat folder: tanpa /data/GoldHEN/scripthook, log gagal ditulis diam-diam
 * (itulah yang terjadi di uji pertama di console). Buat foldernya sekali sebelum menulis.
 */
extern int shv_mkdir(const char *path, int mode) __asm__("sceKernelMkdir");

static void ensure_dir(void)
{
    static int done;
    if (done) return;
    done = 1;
    shv_mkdir("/data/GoldHEN/scripthook", 0777);   /* sudah ada = abaikan error */
}

void plat_log(const char *msg)
{
    FILE *f;
    ensure_dir();
    f = fopen(SHV_DIR "/scripthook.log", "a");
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
