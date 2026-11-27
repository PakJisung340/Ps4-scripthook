/* Satu-satunya batas ke SDK PS4. Implementasi: platform_orbis.c (PS4) atau stub host. */
#ifndef SHV_PLATFORM_H
#define SHV_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#define SHV_DIR "/data/GoldHEN/scripthook"

/* Alamat load eboot (modul utama game). */
uintptr_t plat_main_module_base(void);
/* Mulai thread latar. Return 0 sukses. */
int  plat_start_thread(void *(*fn)(void *), void *arg);
void plat_sleep_ms(unsigned ms);
/* Tulis satu baris ke SHV_DIR/scripthook.log */
void plat_log(const char *msg);
/* Tampilkan notifikasi di layar PS4 (boleh berisi \n). */
void plat_notify(const char *msg);
/* Baca seluruh file; buffer dari malloc, NUL-terminated. Return 0 sukses. */
int  plat_read_file(const char *path, char **buf, size_t *len);

#endif
