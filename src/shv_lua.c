/*
 * Jembatan Lua 5.4 -> native GTA V.
 * Butuh sumber Lua 5.4 di third_party/lua (lihat README). BELUM dikompilasi: Lua tidak
 * tersedia di sesi tempat file ini ditulis.
 *
 * API untuk script:
 *   native.call(hash, "i"|"u"|"f"|"b"|"s"|"p"|"v"|"", args...)
 *       argumen: integer Lua -> int32 (atau 64-bit kalau di luar rentang int32),
 *                float Lua -> float32, boolean -> 0/1, string -> char* sementara,
 *                nil -> 0, native.alloc() -> pointer.
 *       return : "i" int32, "u" uint32, "f" float, "b" boolean, "s" string,
 *                "p" pointer, "v" tiga float (x, y, z), "" tidak ada.
 *   native.alloc(n)  -> pointer ke n byte nol (hanya blok ini yang boleh di-peek/poke)
 *   native.free(p)
 *   native.peek(p, "i32"|"u32"|"f32"|"u8"|"i64" [, offset])
 *   native.poke(p, kind, value [, offset])
 *   native.joaat(str) -> hash Jenkins one-at-a-time (huruf kecil, seperti GET_HASH_KEY)
 *   log(...)         -> tulis ke scripthook.log
 *   CreateThread(fn) -> jalankan fn sebagai coroutine; di dalamnya Wait(ms) menunda
 */
#include "shv_lua.h"
#include "shv_core.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "velora_names.h"
#include "lualib.h"

#define HOOK_EVERY      100000   /* instruksi VM per hook */
#define BUDGET_HOOKS    50       /* 50 x 100000 = 5 juta instruksi per tick, lalu script dihentikan */
#define MAX_BLOCKS      64

static lua_State *L;
static int g_hook_fires;
static struct { void *p; size_t n; } g_blocks[MAX_BLOCKS];

static const char PRELUDE[] =
"local scripts, now = {}, 0\n"
"function GetGameTimer() return now end\n"
"function Wait(ms) coroutine.yield(ms or 0) end\n"
"function CreateThread(fn)\n"
"  scripts[#scripts+1] = { co = coroutine.create(fn), wake = 0 }\n"
"end\n"
"local lastErr\n"
"function __tick(t)\n"
"  now = t\n"
"  if type(onFrame) == 'function' then\n"
"    local ok, e = pcall(onFrame)\n"
"    if not ok and tostring(e) ~= lastErr then lastErr = tostring(e); log('error onFrame: ' .. lastErr) end\n"
"  end\n"
"  local snapshot = {}\n"
"  for i = 1, #scripts do snapshot[i] = scripts[i] end\n"
"  for _, s in ipairs(snapshot) do\n"
"    if s.wake <= t and coroutine.status(s.co) == 'suspended' then\n"
"      local ok, ms = coroutine.resume(s.co)\n"
"      if not ok then\n"
"        log('error script: ' .. tostring(ms))\n"
"        s.dead = true\n"
"      elseif coroutine.status(s.co) == 'dead' then\n"
"        s.dead = true\n"
"      else\n"
"        s.wake = t + (tonumber(ms) or 0)\n"
"      end\n"
"    end\n"
"  end\n"
"  local alive = {}\n"
"  for _, s in ipairs(scripts) do if not s.dead then alive[#alive+1] = s end end\n"
"  scripts = alive\n"
"end\n";


/* Lapisan kompatibilitas Velora: Velora.invoke/Print dan tabel Native (nama -> handler lewat alamat). */
static const char PRELUDE_VELORA[] =
"local T = {}\n"
"for name, a, ty in __NAMES:gmatch('(%S+) (%x+) (%S+)\\n') do T[name] = { tonumber(a, 16), ty } end\n"
"__NAMES = nil\n"
"local blocked = { WAIT = true, START_NEW_SCRIPT = true, START_NEW_SCRIPT_WITH_ARGS = true,\n"
"  START_NEW_SCRIPT_WITH_NAME_HASH = true, START_NEW_SCRIPT_WITH_NAME_HASH_AND_ARGS = true }\n"
"local invoke = native.invoke\n"
"Velora = { invoke = invoke }\n"
"function Velora.Print(m) log('[Print] ' .. (tostring(m):gsub('~%a~', ''))) end\n"
"Native = setmetatable({}, { __index = function(t, k)\n"
"  local e = T[k]\n"
"  if not e then return nil end\n"
"  local f\n"
"  if blocked[k] or e[1] == 0 then f = function() return nil end\n"
"  else local addr, ty = e[1], e[2]; f = function(...) return invoke(addr, ty, ...) end end\n"
"  rawset(t, k, f)\n"
"  return f\n"
"end })\n";

static void budget_hook(lua_State *l, lua_Debug *ar)
{
    (void)ar;
    if (++g_hook_fires > BUDGET_HOOKS)
        luaL_error(l, "script melebihi batas instruksi per tick, dihentikan");
}

static int l_log(lua_State *l)
{
    int n = lua_gettop(l);
    char line[512]; size_t pos = 0;
    for (int i = 1; i <= n; i++) {
        size_t len; const char *s = luaL_tolstring(l, i, &len);
        if (pos + len + 2 < sizeof line) {
            if (i > 1) line[pos++] = ' ';
            memcpy(line + pos, s, len); pos += len;
        }
        lua_pop(l, 1);
    }
    line[pos] = 0;
    plat_log(line);
    return 0;
}

static int block_index(void *p)
{
    for (int i = 0; i < MAX_BLOCKS; i++) if (g_blocks[i].p == p) return i;
    return -1;
}

static int l_alloc(lua_State *l)
{
    lua_Integer n = luaL_checkinteger(l, 1);
    if (n <= 0 || n > 65536) return luaL_error(l, "ukuran alloc 1..65536");
    for (int i = 0; i < MAX_BLOCKS; i++) {
        if (!g_blocks[i].p) {
            void *p = calloc(1, (size_t)n);
            if (!p) return luaL_error(l, "alloc gagal");
            g_blocks[i].p = p; g_blocks[i].n = (size_t)n;
            lua_pushlightuserdata(l, p);
            return 1;
        }
    }
    return luaL_error(l, "terlalu banyak blok alloc (maks %d)", MAX_BLOCKS);
}

static int l_free(lua_State *l)
{
    void *p = lua_touserdata(l, 1);
    int i = block_index(p);
    if (i < 0) return luaL_error(l, "pointer bukan dari native.alloc");
    free(p); g_blocks[i].p = NULL; g_blocks[i].n = 0;
    return 0;
}

static unsigned char *checked_addr(lua_State *l, int pidx, lua_Integer off, size_t width)
{
    void *p = lua_touserdata(l, pidx);
    int i = block_index(p);
    if (i < 0) luaL_error(l, "peek/poke hanya untuk blok dari native.alloc");
    if (off < 0 || (size_t)off + width > g_blocks[i].n) luaL_error(l, "offset di luar blok");
    return (unsigned char *)p + off;
}

static int l_peek(lua_State *l)
{
    const char *k = luaL_checkstring(l, 2);
    lua_Integer off = luaL_optinteger(l, 3, 0);
    if (!strcmp(k, "i32")) { int32_t v;  memcpy(&v, checked_addr(l, 1, off, 4), 4); lua_pushinteger(l, v); }
    else if (!strcmp(k, "u32")) { uint32_t v; memcpy(&v, checked_addr(l, 1, off, 4), 4); lua_pushinteger(l, v); }
    else if (!strcmp(k, "f32")) { float v;    memcpy(&v, checked_addr(l, 1, off, 4), 4); lua_pushnumber(l, v); }
    else if (!strcmp(k, "u8"))  { lua_pushinteger(l, *checked_addr(l, 1, off, 1)); }
    else if (!strcmp(k, "i64")) { int64_t v;  memcpy(&v, checked_addr(l, 1, off, 8), 8); lua_pushinteger(l, v); }
    else return luaL_error(l, "jenis tidak dikenal: %s", k);
    return 1;
}

static int l_poke(lua_State *l)
{
    const char *k = luaL_checkstring(l, 2);
    lua_Integer off = luaL_optinteger(l, 4, 0);
    if (!strcmp(k, "i32") || !strcmp(k, "u32")) { int32_t v = (int32_t)luaL_checkinteger(l, 3); memcpy(checked_addr(l, 1, off, 4), &v, 4); }
    else if (!strcmp(k, "f32")) { float v = (float)luaL_checknumber(l, 3); memcpy(checked_addr(l, 1, off, 4), &v, 4); }
    else if (!strcmp(k, "u8"))  { *checked_addr(l, 1, off, 1) = (unsigned char)luaL_checkinteger(l, 3); }
    else if (!strcmp(k, "i64")) { int64_t v = luaL_checkinteger(l, 3); memcpy(checked_addr(l, 1, off, 8), &v, 8); }
    else return luaL_error(l, "jenis tidak dikenal: %s", k);
    return 0;
}

static int l_joaat(lua_State *l)
{
    size_t len; const unsigned char *s = (const unsigned char *)luaL_checklstring(l, 1, &len);
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h += c; h += h << 10; h ^= h >> 6;
    }
    h += h << 3; h ^= h >> 11; h += h << 15;
    lua_pushinteger(l, h);
    return 1;
}

/* Ring buffer string persisten: pointer tetap valid sampai 128 string berikutnya (native tertentu
 * menyimpan pointer sebentar). */
#define STR_SLOTS 128
#define STR_LEN   256
static char g_strs[STR_SLOTS][STR_LEN];
static unsigned g_str_next;

/* Ubah argumen Lua [first, first+n) menjadi slot 8-byte native. Return 0 sukses, lain = pesan galat sudah dilempar. */
static int marshal_args(lua_State *l, int first, int n, uint64_t *args)
{
    if (n > 32) return luaL_error(l, "terlalu banyak argumen (maks 32)");
    for (int i = 0; i < n; i++) {
        int idx = first + i;
        switch (lua_type(l, idx)) {
        case LUA_TNUMBER:
            if (lua_isinteger(l, idx)) {
                lua_Integer v = lua_tointeger(l, idx);
                args[i] = (v >= INT32_MIN && v <= INT32_MAX) ? (uint64_t)(int64_t)(int32_t)v : (uint64_t)v;
            } else {
                float f = (float)lua_tonumber(l, idx);
                uint32_t bits; memcpy(&bits, &f, 4);
                args[i] = bits;
            }
            break;
        case LUA_TBOOLEAN: args[i] = lua_toboolean(l, idx) ? 1 : 0; break;
        case LUA_TNIL:     args[i] = 0; break;
        case LUA_TLIGHTUSERDATA: args[i] = (uint64_t)(uintptr_t)lua_touserdata(l, idx); break;
        case LUA_TSTRING: {
            size_t len; const char *str = lua_tolstring(l, idx, &len);
            char *slot = g_strs[g_str_next++ % STR_SLOTS];
            if (len >= STR_LEN) return luaL_error(l, "string argumen terlalu panjang (maks %d)", STR_LEN - 1);
            memcpy(slot, str, len + 1);
            args[i] = (uint64_t)(uintptr_t)slot;
            break;
        }
        default: return luaL_error(l, "argumen %d: tipe tidak didukung", i + 1);
        }
    }
    return 0;
}

static float slot_f(uint64_t v) { float f; uint32_t b = (uint32_t)v; memcpy(&f, &b, 4); return f; }

/* kode tipe: i int32, u uint32, b bool, f float, p pointer, s string, v vector3, 0 void */
static int push_ret(lua_State *l, char rk, const uint64_t *r)
{
    switch (rk) {
    case 'i': lua_pushinteger(l, (int32_t)r[0]); return 1;
    case 'u': lua_pushinteger(l, (uint32_t)r[0]); return 1;
    case 'b': lua_pushboolean(l, (uint32_t)r[0] != 0); return 1;
    case 'f': lua_pushnumber(l, slot_f(r[0])); return 1;
    case 'p': lua_pushlightuserdata(l, (void *)(uintptr_t)r[0]); return 1;
    case 's': if (r[0]) lua_pushstring(l, (const char *)(uintptr_t)r[0]); else lua_pushnil(l); return 1;
    case 'v':
        for (int i = 0; i < 3; i++) lua_pushnumber(l, slot_f(r[i]));
        return 3;
    default: return 0;
    }
}

static int l_call(lua_State *l)
{
    uint64_t hash = (uint64_t)luaL_checkinteger(l, 1);
    const char *rk = luaL_checkstring(l, 2);
    int n = lua_gettop(l) - 2;
    uint64_t args[32], r[8];

    marshal_args(l, 3, n, args);
    if (shv_call(hash, args, (uint32_t)n, r) != 0) {
        char m[64]; snprintf(m, sizeof m, "native 0x%llX tidak ada di tabel", (unsigned long long)hash);
        return luaL_error(l, "%s", m);
    }
    return push_ret(l, rk[0], r);
}

/* Velora.invoke(alamat, "void"|"bool"|"int"|"float"|"vector3"|"string", ...): sama dengan loader Velora. */
static int l_invoke(lua_State *l)
{
    uint64_t va = (uint64_t)luaL_checkinteger(l, 1);
    const char *rt = luaL_checkstring(l, 2);
    int n = lua_gettop(l) - 2;
    uint64_t args[32], r[8];
    char rk = 0;

    if (!strcmp(rt, "bool")) rk = 'b';
    else if (!strcmp(rt, "int")) rk = 'i';
    else if (!strcmp(rt, "float")) rk = 'f';
    else if (!strcmp(rt, "vector3")) rk = 'v';
    else if (!strcmp(rt, "string")) rk = 's';
    marshal_args(l, 3, n, args);
    if (shv_call_va(va, args, (uint32_t)n, r) != 0) {
        char m[64]; snprintf(m, sizeof m, "alamat 0x%llX bukan handler native terdaftar", (unsigned long long)va);
        return luaL_error(l, "%s", m);
    }
    return push_ret(l, rk, r);
}

static void run_script_file(const char *name)
{
    char path[256], *buf = NULL; size_t len = 0;
    snprintf(path, sizeof path, SHV_DIR "/%s", name);
    if (plat_read_file(path, &buf, &len) != 0) { plat_log("tidak bisa baca script:"); plat_log(path); return; }
    g_hook_fires = 0;
    if (luaL_loadbuffer(L, buf, len, name) != LUA_OK || lua_pcall(L, 0, 0, 0) != LUA_OK) {
        plat_log("gagal memuat script:"); plat_log(name);
        plat_log(lua_tostring(L, -1));
        lua_pop(L, 1);
    } else {
        plat_log("script dimuat:"); plat_log(name);
    }
    free(buf);
}

int shv_lua_init(void)
{
    static const luaL_Reg libs[] = {
        { LUA_GNAME, luaopen_base }, { LUA_COLIBNAME, luaopen_coroutine },
        { LUA_TABLIBNAME, luaopen_table }, { LUA_STRLIBNAME, luaopen_string },
        { LUA_MATHLIBNAME, luaopen_math }, { LUA_UTF8LIBNAME, luaopen_utf8 },
        { NULL, NULL }
    };
    static const luaL_Reg nat[] = {
        { "call", l_call }, { "invoke", l_invoke }, { "alloc", l_alloc }, { "free", l_free },
        { "peek", l_peek }, { "poke", l_poke }, { "joaat", l_joaat }, { NULL, NULL }
    };
    char *list = NULL; size_t len = 0;

    L = luaL_newstate();
    if (!L) return -1;
    for (const luaL_Reg *p = libs; p->func; p++) { luaL_requiref(L, p->name, p->func, 1); lua_pop(L, 1); }
    /* tanpa io/os/package/debug: script tidak boleh menyentuh file atau proses */
    luaL_newlib(L, nat); lua_setglobal(L, "native");
    lua_pushcfunction(L, l_log); lua_setglobal(L, "log");
    lua_sethook(L, budget_hook, LUA_MASKCOUNT, HOOK_EVERY);

    if (luaL_dostring(L, PRELUDE) != LUA_OK) { plat_log(lua_tostring(L, -1)); return -1; }
    lua_pushstring(L, VELORA_NAMES); lua_setglobal(L, "__NAMES");
    if (luaL_dostring(L, PRELUDE_VELORA) != LUA_OK) { plat_log(lua_tostring(L, -1)); return -1; }

    if (plat_read_file(SHV_DIR "/scripts.txt", &list, &len) != 0) {
        plat_log("scripts.txt tidak ada, mencoba main.lua");
        run_script_file("main.lua");
        return 0;
    }
    for (char *line = strtok(list, "\r\n"); line; line = strtok(NULL, "\r\n")) {
        while (*line == ' ' || *line == '\t') line++;
        if (!*line || *line == '#') continue;
        if (strstr(line, "..") || strchr(line, '/')) { plat_log("nama script ditolak (tidak boleh ada / atau ..):"); plat_log(line); continue; }
        run_script_file(line);
    }
    free(list);
    return 0;
}

void shv_lua_tick(uint32_t now_ms)
{
    if (!L) return;
    g_hook_fires = 0;
    lua_getglobal(L, "__tick");
    lua_pushinteger(L, now_ms);
    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
        plat_log("error di tick:"); plat_log(lua_tostring(L, -1));
        lua_pop(L, 1);
    }
}

void shv_lua_shutdown(void)
{
    if (L) { lua_close(L); L = NULL; }
    for (int i = 0; i < MAX_BLOCKS; i++) { free(g_blocks[i].p); g_blocks[i].p = NULL; }
}
