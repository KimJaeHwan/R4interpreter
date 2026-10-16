#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"

static int write_bytes(lua_State *state, const void *bytes, size_t size, void *context) {
    (void)state;
    return fwrite(bytes, 1, size, (FILE *)context) == size ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    lua_State *state = luaL_newstate();
    if (state == NULL) return 3;
    if (luaL_loadfilex(state, argv[1], "t") != LUA_OK) return 4;
    FILE *out = fopen(argv[2], "wb");
    if (out == NULL) return 5;
    int status = lua_dump(state, write_bytes, out, 1);
    if (fclose(out) != 0) status = 1;
    lua_close(state);
    return status ? 6 : 0;
}
