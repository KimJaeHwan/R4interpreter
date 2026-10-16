#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"

__attribute__((noinline)) int64_t run_lua_chunk(const char *bytecode, int64_t x, int *ok) {
    lua_State *state = luaL_newstate();
    if (state == NULL) return 0;
    lua_pushinteger(state, (lua_Integer)x);
    lua_setglobal(state, "x");
    if (luaL_loadfilex(state, bytecode, "b") != LUA_OK ||
        lua_pcall(state, 0, 1, 0) != LUA_OK ||
        !lua_isinteger(state, -1)) {
        lua_close(state);
        return 0;
    }
    int64_t result = (int64_t)lua_tointeger(state, -1);
    *ok = 1;
    lua_close(state);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    errno = 0;
    char *end = NULL;
    long long x = strtoll(argv[2], &end, 0);
    if (errno || *end != '\0') return 2;
    int ok = 0;
    int64_t result = run_lua_chunk(argv[1], (int64_t)x, &ok);
    if (!ok) return 3;
    printf("%lld\n", (long long)result);
    return 0;
}
