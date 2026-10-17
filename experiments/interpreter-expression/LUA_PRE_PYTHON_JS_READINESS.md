# Lua 단계 정리: Python·JavaScript 적용 직전

## 확보한 결과

디버그 정보가 없는 `lua_branch_call.luac`와 고정 ELF를 분석했다. 평가용 Lua 소스는 분석 입력에 넣지 않았다. [통합 증명](lua_branch_full_flow.json)은 네이티브 함수 `run_lua_chunk`가 받은 64비트 정수 `X`에서 시작해 `printf`의 두 번째 인수까지 다음 **조건부 식**을 연결한다.

```text
X == 0  →  10
X != 0  →  (X + 5) mod 2^64
표시할 때는 signed64로 해석
```

| 검증 지점 | 방법 | 결과 |
|---|---|---|
| 입력 인수 → 첫 Lua 슬롯 → VM 입력 원천 | Ghidra Low P-code와 네이티브 메모리 쓰기 감사 | `X` 전달 확인. `luaL_newstate` 구간의 RBP 보존에는 x86-64 SysV ABI 적용 |
| VM 입력 원천 → 분기·함수 호출·산술 결과 | 한 실행의 연속된 237개(0 경로) 또는 281개(그 외) 네이티브 명령을 P-code로 재생 | guard와 결과식의 부정식을 Z3로 검사해 `unsat`. 각 메모리 접근 주소도 경로 조건에 포함 |
| VM 결과 → Lua 정수 변환 → 네이티브 결과 슬롯 | 연속된 122개 명령을 P-code로 재생 | 임의의 64비트 결과 `P`가 네이티브 결과 슬롯에 저장됨 |
| `lua_close` → `printf` 인수 | 결과 슬롯의 쓰기 감시와 마지막 12개 명령의 P-code 재생 | 관측 실행에서 슬롯 덮어쓰기 0회, `printf` 두 번째 인수는 `P` |

`0`, `9`, `1`, `-1`, `INT64_MAX`, `INT64_MIN` 여섯 입력에서 위 경로를 각각 재생했다. 입력 복사 위치 2곳과 `lua_close` 동안 살아 있는 결과 슬롯에 x86-64 하드웨어 쓰기 감시를 걸었고, 여섯 실행 모두 감시 구간 3개에서 덮어쓰기가 없었다. 감시기가 실제 쓰기를 잡는지는 함수 진입의 첫 스택 쓰기로 매 실행마다 확인했다. [원시 기록](artifacts/lua_branch_full_flow_x0.jsonl)과 다른 입력의 `lua_branch_full_flow_*.jsonl`을 보관한다. 호출 전 VM 경계만 따로 보는 [로컬 증명](lua_branch_local_input.json)도 유지한다.

이것은 **기록된 경로의 다른 진입 레지스터·플래그·첫 메모리 읽기를 고정한 부분 정확성 증명**이다. 아직 임의의 다른 VM 상태가 반드시 같은 경로에 들어간다는 증명은 없다. `strtoll`의 성공적 정수 파싱, ABI 보존 규칙, 관측하지 않은 장기 구간에서의 슬롯 보존을 전제로 둔다. 하드웨어 감시는 여섯 관측 실행을 검증했으며 모든 가능한 실행에 대한 정적 불변식은 아니다. 예외·오류 종료, 다른 코드 버전과 바이트코드는 `unknown`으로 남긴다.

## 다른 Lua 코드와 공통 결과 형식

[이식 준비 JSON](lua_pre_python_js_port.json)은 입력·출력을 `BV64`로, 분기를 언어 이름이 없는 guard/식 트리로 기록한다. 바이너리·바이트코드 해시, 적용 전제, 증거 수준, 미해결 범위를 포함한다. 코드 해시가 다르거나 새 입력의 VM 진입 경로를 확인하지 못하면 `unknown`을 반환한다. 실제로 입력 `2`와 다른 바이트코드에 대한 두 질의를 `unknown`으로 확인했다.

| Lua 바이트코드 | 검증한 사례 | 증거 수준 |
|---|---:|---|
| 분기와 함수 호출 | 6 | 기록된 상태와 명시한 전제 아래 P-code 증명 |
| 단일 `+7` | 8 | 기존 요약의 별도 입력 차등 검증 |
| 단일 `+11` | 8 | 같은 요약을 다른 명령 워드에 적용한 차등 검증 |
| 연속 `+7; +11` | 6 | 두 handler와 fetch 연결 요약의 차등 검증 |

총 28개 사례를 저장된 ELF와 바이트코드로 다시 실행해 예측 결과와 비교했다. 뒤의 세 바이트코드에 분기 예제와 같은 입력부터 반환까지의 증명 등급을 부여하지 않았다. 분석 절차는 언어별 opcode 의미표 대신 네이티브 P-code, 메모리 버전, 분기 조건, 호출·반환 경계를 사용한다. Lua 고유 코드는 VM 슬롯과 바이트코드의 위치를 공통 입력·출력에 연결하는 adapter에 한정한다.

## 재현

저장소 루트에서 기존 `z3-solver`, `capstone`, `pyelftools` 환경을 사용한다. 저장된 추적과 Bundle이 포함되어 있으므로 Ghidra나 `ptrace` 없이 증명 재생이 가능하다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_lua_branch_cutpoint.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_lua_call_bridge.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_lua_local_input.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_lua_full_flow.py
python3 experiments/interpreter-expression/summarize_lua_branch_call.py
python3 experiments/interpreter-expression/export_lua_portability_gate.py
```

원시 추적을 새로 만들 때는 Linux x86-64에서 `trace_input_provenance.py --capture-full-flow --hardware-watch --markers-only`를 사용한다. `artifacts/lua_main_bundle.tar.gz`는 기존 Bundle에 없던 `main`의 P-code를 포함하도록 Ghidra 12.0.4 exporter로 별도 생성했다. exporter는 `/workspace/daasdmlkas`에서 **읽기만** 했고, 출력은 R4interpreter와 작업용 디렉터리에 저장했다.

## Python·JavaScript에 적용하기 전에 고정할 인터페이스

다음 언어에서는 위 JSON의 bitvector·메모리·case·identity·`unknown` 구조를 그대로 사용한다. 새 adapter는 (1) 실행 코드와 바이트코드의 버전, (2) VM 상태에서 입력값을 읽는 경계, (3) 호출·예외·반환 경계, (4) 동적 코드 변경 여부를 제공해야 한다. Python의 객체 연산과 JavaScript의 객체·JIT·deopt는 현재 Lua 정수 모델에 없으므로 새 효과나 `unknown`으로 표현해야 한다. **다음 실제 작업은 Python 또는 JavaScript 대상 하나를 선택해 이 인터페이스에 연결하는 실험**이다.
