# 실행기 입력에서 Lua VM 결과까지: 1~3단계 실험 결과

같은 고정 주소 ELF와 디버그 정보가 제거된 `.luac`를 사용했다. 네이티브 `run_lua_chunk` 진입부터 첫 `luaV_execute` 덧셈 저장까지 명령 단위로 추적하고, 메모리 피연산자의 실제 주소·폭·전후값을 기록했다. 분석 입력은 ELF, Ghidra Bundle, 원시 추적 및 바이트코드 파일이다. 원본 Lua 소스나 Lua opcode 이름으로 데이터 경로를 연결하지 않았다.

## 1. 입력값의 전달 경로

입력 `9`의 한 실행에서 다음 값과 주소를 관측했다. 실제 힙 주소는 실행마다 바뀌지만, 읽기와 앞선 쓰기가 같은 주소를 가리키는 관계는 입력 `0`, `9`, `19088743` 및 뒤의 경계값에서도 확인했다.

| 네이티브 주소 | 실제 동작 | 입력 `9`에서 관측한 관계 |
|---|---|---|
| `0x40149b`, `0x4014b3` | 실행기 인자 `RSI`를 `RBP`에 보관한 뒤 다시 `RSI`에 전달 | 함수 진입 `RSI=9`, 호출 직전 `RSI=9` |
| `0x402a04` | 입력 정수를 첫 Lua 저장 위치에 기록 | `memory[A] ← 9` |
| `0x411b50`, `0x411b54` | 같은 위치에서 읽어 다른 위치에 복사 | `memory[A]=9 → memory[B] ← 9` |
| `0x416ea1`, `0x416ea7` | 복사된 값을 VM 피연산자 위치로 전달 | `memory[B]=9 → memory[C] ← 9` |
| `0x417ce7`, `0x417cea` | `C`를 읽어 `R12=7`과 더하고 결과를 저장 | `memory[C]=9 → memory[C] ← 16` |

[`trace_input_provenance.py`](trace_input_provenance.py)는 각 명령의 명시적 x86 메모리 피연산자를 디코딩해 실행 전후 값을 자식 프로세스에서 읽는다. 첫 덧셈까지 약 5.3만 명령을 진행하며 입력값과 같은 8바이트 메모리 접근 및 선택한 지점을 JSONL로 남긴다. 입력 `0`은 같은 값의 우연한 출현이 많아 선택 지점만 기록했다. 원시 기록은 `artifacts/lua_provenance_*.jsonl`에 있다.

## 2. 선택된 P-code 경로의 계산식

[`replay_input_path.py`](replay_input_path.py)는 저장된 Bundle에서 위 주소의 `COPY`, `LOAD`, `STORE`를 따라 `X`를 전달한다. 바이트코드 처리 구간 `0x4164d0`의 `INT_RIGHT`와 `0x4164d7`의 `INT_SUB`는 고정 명령 값의 상위 바이트 `134`에서 `127`을 빼 `7`을 만든다. `0x417ce4`의 `INT_SEXT`, `0x417ce7`의 `LOAD`·`INT_ADD`, `0x417cea`의 `STORE`를 재생한 식은 다음과 같다.

```text
result_word = (X + 7) mod 2^64
program_output = signed64(result_word)
```

선택한 P-code 연산 21개를 실제 레지스터·메모리 값과 대조했다. 해당 식과 `X + 7`의 비동치 조건은 Z3에서 `unsat`이었다. [기계 판독 결과](provenance_replay_result.json)에는 각 입력의 실제 메모리 주소, 값, 추적 해시를 기록했다. 이 SMT 결과는 **선택해 재생한 경로의 대수 관계**를 검증한다. 전체 인터프리터 또는 다른 경로의 의미를 증명하지는 않는다.

## 3. 경로 조건과 별도 입력

덧셈 직전 `0x4164e5`에서 피연산자의 1바이트 태그 값 `3`을 읽었고, `0x4164e9`에서 `3`과 비교한 뒤 Bundle의 `0x4164ec` `CBRANCH`가 `0x417ce4`로 갔다. 이것은 관측한 **로컬 정수 덧셈 경로 조건**이다. 현재 ELF와 바이트코드 해시, 입력 파싱 성공, 이 태그 및 분기, 관측한 메모리 연결을 적용 범위로 둔다. 모든 가능한 입력에 대한 완전한 진입 조건은 아직 유도하지 않았다.

입력 `0`, `9`를 기준으로, 계산식 도출에 사용하지 않은 6개 입력을 별도로 실행했다. 8개 모두 첫 VM 호출의 **262개 네이티브 명령 주소와 각 후속 주소의 전체 순서**가 같았고, 피연산자 값·결과 저장값·프로그램 출력이 식과 일치했다. `19088743`은 값이 다른 메모리와 우연히 겹칠 가능성을 줄이기 위한 출처 추적용 값으로 추가했다.

| 별도 입력 `X` | 관측 출력 | 확인한 지점 |
|---:|---:|---|
| `1` | `8` | 양수 |
| `-1` | `6` | 음수 |
| `9223372036854775800` | `9223372036854775807` | 최대값 직전 |
| `9223372036854775801` | `-9223372036854775808` | 64비트 오버플로 경계 |
| `9223372036854775807` | `-9223372036854775802` | 최대값 |
| `-9223372036854775808` | `-9223372036854775801` | 최소값 |

[경로·출력 결과](guard_scope_result.json)와 `artifacts/lua_trace_*.csv`에 각 실행의 근거를 남겼다. 경로 일치는 실행 후 확인한 서명이며, 미래 입력을 분류할 수 있는 완전한 정적 guard는 아니다.

## 한계

- 입력 출처 추적기는 명시적 1·2·4·8바이트 메모리 피연산자를 기록한다. 암묵적 스택 접근, 세그먼트·벡터 접근 및 선택하지 않은 P-code 연산을 모두 추적하는 범용 데이터 흐름 엔진은 아니다. 선택한 읽기 시점의 실제 값과 앞선 쓰기 주소를 대조했지만, 모든 중간 메모리 별칭이나 호출 효과를 증명하지 않았다.
- 식은 현재 바이트코드의 첫 VM 호출에서 관측한 경로에 대한 것이다. 다른 바이트코드, 태그·분기가 달라지는 경로, 오류 경로의 결과는 `unknown`이다.
- `daasdmlkas` 파일은 수정하지 않았다. 기존 Bundle 형식과 P-code를 R4interpreter의 실험 코드에서 읽었다.

## 재현

Python 3.11 이상과 `capstone`, `pyelftools`, `z3-solver`가 필요하다. 이 디렉터리를 작업 디렉터리로 하여 다음을 실행한다. `ptrace` 가능한 Linux x86-64와 저장된 비 PIE ELF가 필요하다.

```bash
python trace_input_provenance.py ./lua_interpreter_fixture ./lua_chunk.luac 9 artifacts/lua_provenance_x9_recheck.jsonl --limit 100000
python replay_input_path.py artifacts/lua_bundle.tar.gz /tmp/provenance_recheck.json artifacts/lua_provenance_x9_recheck.jsonl
gcc -O2 -Wall -Wextra -Wformat=2 -Werror -o /tmp/r4_ptrace_instruction_trace ptrace_instruction_trace.c
/tmp/r4_ptrace_instruction_trace 415440 100000 /tmp/lua_trace_one_recheck.csv ./lua_interpreter_fixture ./lua_chunk.luac 1
python guard_scope_probe.py
```

`guard_scope_probe.py`는 저장된 8개 VM 추적을 읽고 현재 ELF를 다시 실행한다. 재추적한 단일 CSV를 검사하려면 원래 파일을 교체하거나 스크립트의 사례 경로를 맞춘다.
