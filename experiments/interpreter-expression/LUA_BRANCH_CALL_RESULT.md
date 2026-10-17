# 실제 Lua 분기와 함수 호출 실험

## 대상과 분석 입력

Lua 5.4.8로 디버그 정보를 제거한 [`lua_branch_call.luac`](lua_branch_call.luac)를 만들었다. 평가용 소스는 [`lua_branch_call_source.lua`](lua_branch_call_source.lua)이다. 스크립트는 입력이 0일 때 `adjust(5)`, 그 외에는 `adjust(x)`를 호출하고, 호출된 함수는 인자에 5를 더한다. **분석 절차는 소스를 읽지 않는다.** 기존 고정 ELF, `.luac`, Ghidra Bundle, 네이티브 추적을 입력으로 사용했다.

| 입력 | 호출자에서 관측한 바이트코드 인덱스 | 호출된 함수의 진입 값 | 핸들러 payload | 스크립트 출력 |
|---:|---|---:|---:|---:|
| 0 | 0,1,2,3,5,6,7 | 5 | 10 | 10 |
| 9 | 0,1,2,3,9,10,11 | 9 | 14 | 14 |
| -1 | 0,1,2,3,9,10,11 | -1 | 4 | 4 |
| `INT64_MAX` | 0,1,2,3,9,10,11 | `INT64_MAX` | `INT64_MIN+4` | `INT64_MIN+4` |

[`bytecode_handler_map.py`](bytecode_handler_map.py)를 확장해 호출자와 피호출자가 가진 서로 다른 런타임 코드 영역을 각각 `.luac`의 연속된 32비트 워드 구간에 맞췄다. 네 입력 모두 피호출자의 인덱스 0과 2가 같은 영역에 있으며, 인덱스 0의 분배 대상은 이전 덧셈 실험과 같은 `0x4164b8`이었다. 인덱스 0의 실행 구간에는 네이티브 덧셈 주소 `0x417ce7`이 있다. 각 위치 대응은 원시 [추적](artifacts/lua_branch_call_0.csv), [대응 결과](lua_branch_call_map_0.json)와 다른 입력의 동명 파일에 저장했다. 영역 구분에는 이 작은 fixture에서 128바이트보다 큰 주소 점프를 새 코드 영역으로 보는 휴리스틱을 썼다.

기존 [P-code 핸들러 요약](handler_summary_plus7.json)을 호출된 함수의 덧셈 구간에 그대로 적용했다. 네 입력에서 읽기와 순서 있는 두 쓰기가 원시 추적과 일치했다. [공통 투영기](project_lua_handler_logic.py)가 VM 슬롯의 8바이트 값을 기호 `Y`로 묶어 `Y + 5`를 도출했고, 이 **핸들러 경로 안의 값 축약**은 Z3로 증명됐다. 이번 호출에서는 진입 `RDX`가 입력값이 아니라 `0xffffffff`였으므로, 투영기가 입력을 슬롯 메모리에서만 바인딩하도록 확장했다. 이전 `X + 7` 추적의 레지스터와 메모리 동시 바인딩도 다시 확인했다.

## 공통 형식의 현재 범위

[결과 JSON](lua_branch_call_relation.json)은 공통 `guarded_input_relation` 형식에 두 관측 경로를 넣는다. 현재의 전체 스크립트 후보식은 `X=0 → 10`, `X≠0 → X+5`다. **CLI 입력 `X`에 대한 두 guard와 최종 출력식은 모든 입력에 대해 증명되지 않았다.** 코드가 기록한 `guard_proven: false`, `value_proven: false`는 이 차이를 나타낸다.

이번에는 VM 내부 경계에서 한 단계를 더 연결했다. [분기 cutpoint 증명](lua_branch_cutpoint_guard.json)은 네이티브 `0x417e50`에서 `[RDX]`의 8바이트를 `Y`로 두고 9개 명령의 84개 P-code 연산을 재생하여 `Y=0`/`Y≠0`을 확인했다. [호출 경로 증명](lua_branch_call_bridge.json)은 호출 직전 슬롯까지 각각 194개/238개 네이티브 명령을 재생했다. 이때 `9` 경로의 분기값 `Y`와 호출 인수 원천 `A`는 **서로 다른 주소**이므로 별도 기호로 취급했다. 이 경계에서 `Y=0 → callee_input=5`, `Y≠0 → callee_input=A`가 증명됐다.

Astra 검토에 따라 시작점을 24개 명령 앞의 첫 `0x416ea1` 읽기로 옮겼다. [로컬 입력 증명](lua_branch_local_input.json)은 그 읽기값을 `X_local`로 정의한다. P-code 재생과 Z3 부정식의 `unsat` 결과로 `X_local`이 분기 피연산자에 전달되고, `9` 경로에서 같은 원천을 다시 읽어 호출 인수로 전달됨을 확인했다. 두 읽기 사이 원천 8바이트와 겹치는 쓰기가 없다는 것도 확인했다. 현재 증명된 로컬 관계는 다음과 같다.

| 경계 입력 | 분기 조건 | 호출된 함수의 진입 슬롯 | 호출된 산술 핸들러 |
|---|---|---|---|
| `X_local` | `X_local = 0` | `5` | `callee_input + 5` |
| `X_local` | `X_local ≠ 0` | `X_local` | `callee_input + 5` |

이 결과는 각 관측 경로의 **입력값 이외 네이티브 레지스터·플래그·첫 메모리 읽기를 고정한 조건부 증명**이다. `X_local`과 CLI 입력 `X`의 연결, 호출 후 스크립트 반환값까지의 전이, 그리고 다른 VM 상태에서도 같은 경로로 진입하는 조건은 남아 있다. 따라서 전체 스크립트의 증명 플래그는 여전히 `false`다. 기존 `daasdmlkas` 파일은 수정하지 않았다.

## 재현

저장소 루트에서 다음 명령을 실행한다. `python`은 기존 실험의 `z3-solver` 환경을 사용한다. 원시 추적은 포함되어 있으므로 아래 명령은 추적을 다시 수집하지 않는다.

```bash
python3 experiments/interpreter-expression/bytecode_handler_map.py experiments/interpreter-expression/artifacts/lua_branch_call_0.csv /tmp/lua_branch_map_recheck.json experiments/interpreter-expression/lua_branch_call.luac
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_transition_summary.py experiments/interpreter-expression/handler_summary_plus7.json experiments/interpreter-expression/lua_interpreter_fixture experiments/interpreter-expression/artifacts/lua_branch_call_handler_x0.jsonl /tmp/lua_branch_handler_recheck.json
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_lua_handler_logic.py --summary experiments/interpreter-expression/handler_summary_plus7.json --trace experiments/interpreter-expression/artifacts/lua_branch_call_handler_x0.jsonl --binary experiments/interpreter-expression/lua_interpreter_fixture --output /tmp/lua_branch_logic_recheck.json
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_lua_branch_cutpoint.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_lua_call_bridge.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_lua_local_input.py
python3 experiments/interpreter-expression/summarize_lua_branch_call.py
```

새 원시 추적을 수집할 때는 기존 `ptrace_instruction_trace.c`를 빌드한 뒤 ELF의 `luaV_execute` 진입 `0x415440`을 지정한다. 핸들러 메모리 효과 기록은 `trace_input_provenance.py --capture-handler --markers-only`를 사용한다. 이번 호출 연결 추적은 다음 명령으로 각각 수집한다. 저장된 추적을 사용할 때 재수집은 필요 없다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_input_provenance.py ./experiments/interpreter-expression/lua_interpreter_fixture ./experiments/interpreter-expression/lua_branch_call.luac 0 experiments/interpreter-expression/artifacts/lua_branch_bridge_x0.jsonl --limit 100000 --capture-bridge --markers-only
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_input_provenance.py ./experiments/interpreter-expression/lua_interpreter_fixture ./experiments/interpreter-expression/lua_branch_call.luac 9 experiments/interpreter-expression/artifacts/lua_branch_bridge_x9.jsonl --limit 100000 --capture-bridge --markers-only
```

## 다음 실험

1. CLI 정수 파싱부터 `0x416ea1` 첫 읽기까지 메모리 출처를 추적해 `X_local = X`를 증명한다. 여러 쓰기와 부분 쓰기는 메모리 버전으로 검증하고, 경로가 갈라지면 조건부 요약을 분리한다.
2. 호출 결과 슬롯에서 Lua 반환 및 네이티브 출력까지 이어지는 suffix를 재생해 `callee_input + 5`가 실제 반환값으로 선택되는 조건을 증명한다.
3. `0`, `9` 외 경계값과 복수 바이트코드에 대해 같은 요약 입력·출력 형식을 적용하고, 새로운 경로는 미확인 상태로 남기는지 확인한다.
