#ifndef SHV_LUA_H
#define SHV_LUA_H

#include <stdint.h>

/* Buat state Lua dan muat script dari SHV_DIR/scripts.txt. Dipanggil dari tick pertama. */
int  shv_lua_init(void);
/* Jalankan satu tick (now_ms = GET_GAME_TIMER). */
void shv_lua_tick(uint32_t now_ms);
void shv_lua_shutdown(void);

#endif
