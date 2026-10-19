/* Fixed Lua 5.4 script oracle. Analysis uses native/P-code traces separately. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "branch") && strcmp(argv[1], "string"))) return 2;
    lua_State *L = luaL_newstate();
    if (!L) return 3;
    int branch = strcmp(argv[1], "branch") == 0;
    lua_pushinteger(L, branch ? 0 : 1);
    lua_setglobal(L, "case_mode");
    if (branch) {
        char *end = NULL;
        errno = 0;
        long long value = strtoll(argv[2], &end, 10);
        if (errno || end == argv[2] || *end) { lua_close(L); return 2; }
        lua_pushinteger(L, (lua_Integer)value);
        lua_setglobal(L, "case_number");
    } else {
        lua_pushstring(L, argv[2]);
        lua_setglobal(L, "case_text");
    }
    if (luaL_loadfilex(L, argv[3], "t") != LUA_OK ||
            lua_pcall(L, 0, 1, 0) != LUA_OK) {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        lua_close(L);
        return 4;
    }
    if (branch) {
        if (!lua_isinteger(L, -1)) { lua_close(L); return 5; }
        printf("%lld\n", (long long)lua_tointeger(L, -1));
    } else {
        size_t length;
        const char *value = lua_tolstring(L, -1, &length);
        if (!value || fwrite(value, 1, length, stdout) != length || putchar('\n') == EOF) {
            lua_close(L);
            return 5;
        }
    }
    lua_close(L);
    return 0;
}
