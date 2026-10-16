# 첫 실제 실행 추적 결과

입력 `9`로 작은 ELF와 Lua 5.4.8 실행기를 각각 한 번 실행했다. 두 실행의 출력은 `16`이었다. [`ptrace_instruction_trace.c`](ptrace_instruction_trace.c)는 고정 주소 함수 진입에 중단점을 놓고, 그 호출이 반환될 때까지 명령 단위로 실행한다. 명령 주소와 레지스터 전후 상태, RAX/RDX가 가리키는 8바이트 후보 메모리 값을 기록한다. **모든 메모리 피연산자를 디코딩하는 추적기는 아니다.**

| 기록 | 명령 실행 수 | Bundle과 주소 대응 | 근거 |
|---|---:|---:|---|
| [`add7` 작은 ELF](elf_trace_x9_result.json) | 2 | 2/2 | RDI `9` → RAX `16`; P-code `INT_ADD` |
| [`luaV_execute` 첫 호출](lua_trace_x9_result.json) | 262 | 262/262 | VM 내부 165개 명령; 조건 분기 19개 모두 Ghidra 후속 주소와 일치 |

Lua 경로의 `0x417ce7` 명령은 Bundle에서 `LOAD`와 `INT_ADD`(P-code 순번 5) 등을 가진다. 해당 실행에서 RAX가 가리키는 메모리는 `9`, R12는 `7`이었고, 명령 뒤 R12는 `16`이었다. 이어진 `0x417cea`의 `STORE` 뒤 메모리도 `16`이었다. 따라서 **이 한 실행의 VM 내부 덧셈**은 P-code 연산과 실제 값이 맞는다. [원시 ELF 기록](artifacts/elf_trace_x9.csv)과 [원시 Lua 기록](artifacts/lua_trace_x9.csv)을 함께 보관했다.

이번 추적은 `luaV_execute`의 첫 진입부터 반환까지다. 그 전에 실행기가 입력을 Lua 전역과 VM 스택으로 전달한 과정은 기록하지 않았다. 입력 `x`가 읽힌 메모리 `9`와 같다는 데이터 출처 증명, `7`의 출처, 경로 guard, 다른 입력에 대한 계산식은 아직 없다. 결과 등급은 `observed`이며 `x + 7`을 일반식으로 보고하지 않는다.

재현 명령은 다음과 같다. 실행 파일은 이 디렉터리에 저장된 당시 빌드이며, 함수 주소는 `nm`으로 확인한 값이다.

```bash
gcc -O2 -Wall -Wextra -Wformat=2 -Werror -o /tmp/r4_ptrace_instruction_trace ptrace_instruction_trace.c
/tmp/r4_ptrace_instruction_trace 4011a0 100 /tmp/elf_trace_recheck.csv ./elf_expression_fixture 9
/tmp/r4_ptrace_instruction_trace 415440 100000 /tmp/lua_trace_recheck.csv ./lua_interpreter_fixture ./lua_chunk.luac 9
python3 trace_bundle_compare.py artifacts/elf_bundle.tar.gz artifacts/elf_trace_x9.csv elf_trace_x9_result.json
python3 trace_bundle_compare.py artifacts/lua_bundle.tar.gz artifacts/lua_trace_x9.csv lua_trace_x9_result.json
```

## 다음 관문

실행기 진입부터 VM의 덧셈까지 입력값의 전달을 추적한다. 메모리 피연산자 주소·폭·값을 실제 명령에서 디코딩해 기록하고, 적어도 입력 `0`, `1`, `9`에서 출처 경로를 확인한다. 그 뒤 미사용 입력에 대한 식을 판정한다.
