# Lua 인터프리터 계산식 실험

[실험 계획과 판정 기준](interpreter_expression_experiment_plan.md). `daasdmlkas` 기준 커밋은 `3a274f93d455d3caaebf72365e64820770341787`이며, 이 저장소는 그 프로젝트의 코드를 복사하거나 수정하지 않는다.

## 현재 결과

| 대상 | 분석 결과 | 확인 범위 |
|---|---|---|
| 합성 P-code | 8비트 `x+7`, `7-x`, `x+7-3` 식 투영 | 각 256개 입력, SMT 및 오류 주입 |
| 작은 실제 ELF | 64비트 `x+7` 식 투영 | ELF 직접 실행 137개 입력, 사양과 SMT 비교 |
| Lua 5.4.8 실행기 | 정적 슬라이스에는 미해결 의존 4개·6개; 관측 경로의 P-code 재생으로 `(X+7) mod 2^64` 도출 | 첫 VM 호출의 동적 경로, 별도 입력 6개와 경계값 확인 |
| 공통 전이 요약 v0 | Lua 한 handler 경로의 P-code 265개를 식/효과로 저장; 동일 적용기로 작은 ELF도 처리 | Lua 바이트코드 2개 × 8 입력, 네이티브 ELF 5 입력 차등 확인 |
| 두 handler 합성 | 기존 Lua 요약의 출력에서 5개 명령의 fetch/decode/dispatch를 거쳐 다음 handler 입력 계산 | `x+7; +11` 바이트코드 6 입력, 둘째 진입 snapshot 입력 없이 차등 확인 |
| 공통 입력식 투영 | 기존 Lua 핸들러·연결 요약과 작은 VM 경로 요약에 같은 기호 투영기 적용 | Lua `X+7`, `X+11`, 두 핸들러 `X+18`; 작은 VM 30개 평가 중 28 pass·2 accepted_unknown |
| Lua 분기·함수 호출 | VM 입력부터 `printf` 인수까지 `X=0 → 10`, 그 외 `→ X+5`를 조건부 P-code 경로로 증명 | 2개 분기·6개 입력. ABI·진입 상태·경로 전제가 필요하며 전체 경로 완전성은 미증명 |
| Python 3.13·JavaScript Ignition | 양쪽의 bytecode fetch→native handler 분배를 실제 주소로 연결하고 같은 guard/식 적용기에 연결 | 각 2개 native 분기 경로, 14개 출력 차등 검증. 계산식은 아직 표본 기반 후보이며 native 값 증명은 미완료 |

Lua의 `luaV_execute`는 Ghidra Bundle에서 정규화되지만 3,670개 명령, 1,608개 SSA JOIN, 442개 미해결 읽기 노드를 가진다. [루트 결과](lua_root_probe_result.json), [VM 결과](lua_vm_probe_result.json), [Bundle 전체 기록](lua_bundle_stats.json)을 구분해서 읽어야 한다. 전체 기록은 61번째 함수의 관측 범위 오류로 중단됐다.

[첫 실제 실행 추적](FIRST_TRACE_RESULT.md)에서는 입력 `9`의 Lua VM 내부 덧셈 `9 + 7 = 16`을 P-code `INT_ADD`와 대조했다. 이것은 한 경로의 관측 결과이며 아직 입력에 대한 일반식은 아니다.

[바이트코드→네이티브 처리 구간 대응](BYTECODE_HANDLER_RESULT.md)에서는 입력 `9`, `0`의 실행 기록을 대조했다. 실행된 바이트코드 인덱스 `0, 1, 2, 4`가 두 입력에서 같은 네이티브 진입 주소로 분기했고, 인덱스 `2`의 구간에 실제 덧셈이 있었다.

[입력 출처·P-code 계산식·적용 범위](INPUT_PROVENANCE_RESULT.md)에서는 실행기 인자에서 VM 피연산자까지 실제 메모리 주소를 연결했다. 선택한 경로의 식은 `signed64((X+7) mod 2^64)`이며, 별도 입력 6개와 정수 경계값에서 같은 VM 경로와 출력을 확인했다. 다른 경로는 아직 `unknown`이다.

[첫 공통 전이 요약 결과](TRANSITION_SUMMARY_RESULT.md)에서는 `x+7`에서 만든 조건부 상태 전이를 `x+11`의 같은 처리 구간에 재추출 없이 적용했다. 작은 네이티브 ELF도 같은 JSON 구조와 적용기를 사용한다. 이것은 한 경로의 차등 검증 결과이며 전체 Lua handler나 다른 언어의 분석 결과는 아니다.

[두 handler 합성 결과](TWO_HANDLER_COMPOSITION_RESULT.md)에서는 명령 위치와 VM 슬롯이 다른 `x+7; +11` 바이트코드에 기존 요약을 적용하고, 그 사이 fetch/decode/dispatch를 P-code로 연결했다. 첫 처리 구간의 출력과 바이트코드·읽기 전용 점프 테이블에서 두 번째 진입 상태를 예측했다.

[입력 수준 식 축약 결과](../vm-transition-testbed/results/LOGIC_PROJECTION_RESULT.md)에서는 두 엔진의 요약을 같은 `logic_projection.py`로 합성하고 SMT 동치 확인 후 긴 P-code 식을 간단한 `X` 식으로 줄였다. Lua의 축약 범위는 현재 마지막 숫자 핸들러까지이며 최종 반환 경로는 포함하지 않는다.

[Lua 분기·함수 호출 실험](LUA_BRANCH_CALL_RESULT.md)은 호출 전후 두 바이트코드 코드 영역을 실제 추적으로 연결했다. 네이티브 P-code 재생으로 VM 입력의 분기·호출·덧셈 결과와 Lua 반환 경로를 연결했다. [Python·JavaScript 적용 직전 정리](LUA_PRE_PYTHON_JS_READINESS.md)는 여섯 입력의 조건부 증명, 다른 세 Lua 바이트코드의 22개 차등 검증, 새 경로의 `unknown` 판정을 구분한다.

[Python·JavaScript 첫 교차 결과](PYTHON_JS_FIRST_RESULT.md)는 CPython 3.13.5와 Node 24.19.0 Ignition의 실제 bytecode→native dispatch 대응, 공통 값 sort 형식, 14개 출력 검증을 기록한다. 후속 [전체 함수 경로 결과](PYTHON_JS_FULL_FLOW_RESULT.md)는 제한된 VM 입력 상태에서 분기·호출·덧셈·반환을 P-code와 하드웨어 감시점으로 연결한다. 기존 portable 적용기의 새 CLI 입력은 계속 `unknown`으로 둔다.

## 파일

- `expression_probe.py`, `elf_expression_probe.py`, `lua_root_probe.py`, `lua_vm_probe.py`: 분석 코드와 대응하는 `*_result.json`.
- `elf_expression_fixture.c`, `lua_interpreter_fixture.c`: 네이티브 입력 프로그램. 같은 이름의 확장자 없는 파일은 당시 빌드한 ELF이다.
- `lua_chunk_source.lua`: 평가용 원본. 분석 입력은 디버그 정보를 제거한 `lua_chunk.luac`이다. `lua_compile_chunk.c`는 바이트코드 생성 도구다.
- `artifacts/elf_bundle.tar.gz`, `artifacts/lua_bundle.tar.gz`, `artifacts/lua_main_bundle.tar.gz`: admission 가능한 Ghidra 12.0.4 Bundle. 마지막 Bundle은 `main`의 반환 출력 연결을 포함한다. [SHA-256 목록](artifacts/SHA256SUMS)에 아카이브 해시를 기록했다. JSON 결과의 `/workspace/scratch` 경로는 원래 실험 당시 경로다.
- `ptrace_instruction_trace.c`, `trace_bundle_compare.py`: 첫 명령 단위 추적 및 Bundle 대조 도구. 원시 CSV와 요약 JSON은 [첫 추적 기록](FIRST_TRACE_RESULT.md)에 연결했다.
- `bytecode_handler_map.py`: 바이트코드 명령 읽기와 VM 간접 분기를 원시 추적·Bundle에 대조한다. 결과와 적용 범위는 [바이트코드 대응 기록](BYTECODE_HANDLER_RESULT.md)에 있다.
- `trace_input_provenance.py`, `replay_input_path.py`, `guard_scope_probe.py`: 입력 메모리 출처 추적, 선택된 P-code 경로 재생, 별도 입력과 경로 비교. 결과와 재현법은 [입력 출처 결과](INPUT_PROVENANCE_RESULT.md)에 있다.
- `pcode_transition_summary.py`, `build_native_transition_summary.py`, `apply_transition_summary.py`, `validate_transition_summaries.py`: P-code 경로 요약 생성, 공통 요약 적용 및 차등 검증. [요약 결과](TRANSITION_SUMMARY_RESULT.md)에 파일과 재현법을 기록했다.
- `build_lua_dispatch_bridge.py`, `compose_lua_two_adds.py`, `validate_lua_composition.py`: 처리 구간 사이의 P-code 전이 생성과 두 정수 명령 합성. [합성 결과](TWO_HANDLER_COMPOSITION_RESULT.md)에 범위와 재현법을 기록했다.
- `logic_projection.py`, `project_lua_handler_logic.py`, `project_lua_two_adds_logic.py`: 언어에 의존하지 않는 식·효과 투영기와 Lua 경계 adapter. [공통 축약 결과](../vm-transition-testbed/results/LOGIC_PROJECTION_RESULT.md)에 실험 결과를 기록했다.
- `prove_lua_full_flow.py`, `export_lua_portability_gate.py`: Lua 분기 경로의 입력·VM·반환 연결과 다른 바이트코드의 검증 등급을 공통 형식으로 내보낸다. [Lua 단계 정리](LUA_PRE_PYTHON_JS_READINESS.md)에 범위와 재현법이 있다.
- `python_branch_fixture.py`, `js_branch_fixture.js`, `trace_cross_native.py`, `cross_dispatch_pcode.py`, `collect_cross_language.py`, `portable_guard_eval.py`: 두 새 인터프리터의 경계 추적·P-code·공통 후보 적용기. [교차 결과](PYTHON_JS_FIRST_RESULT.md)에 재현법과 한계를 기록했다.
- `trace_cross_full_flow.py`, `prove_cross_full_flow.py`: Python·JavaScript의 함수 입력부터 호출자 복귀까지의 조건부 P-code 연결과 하드웨어 인수 감시. [전체 함수 경로 결과](PYTHON_JS_FULL_FLOW_RESULT.md)에 적용 범위를 기록했다.

## 재현

Python 3.11 이상과 `daasdmlkas`의 Python 의존성이 필요하다. `daasdmlkas`를 이 저장소의 형제 디렉터리에 기준 커밋으로 체크아웃한다. 다른 위치라면 `DAASDMLKAS_REPO` 환경 변수를 지정한다. 스크립트에는 해당 저장소의 `src`와 `tests/intra`, 이 디렉터리를 `PYTHONPATH`로 전달한다.

```bash
cd experiments/interpreter-expression
export DAASDMLKAS_REPO=/workspace/daasdmlkas
export PYTHONPATH="$DAASDMLKAS_REPO/src:$DAASDMLKAS_REPO/tests/intra:$PWD"
tar -xzf artifacts/elf_bundle.tar.gz -C artifacts
tar -xzf artifacts/lua_bundle.tar.gz -C artifacts
python expression_probe.py
python elf_expression_probe.py artifacts/e88ce248bbd68f05e27c712aeb371d775ff51b77880c6845e9739850dc3a48d4
python lua_root_probe.py artifacts/df2f4d4cd7f97ad377a617930f5942155ced9101ca18cbc03cfd4478d6ae8785
python lua_vm_probe.py artifacts/df2f4d4cd7f97ad377a617930f5942155ced9101ca18cbc03cfd4478d6ae8785
```

`DAASDMLKAS_REPO` 값은 체크아웃 위치에 맞춘다. Bundle 추출 디렉터리는 해당 머신의 사용자 소유이며 다른 사용자에게 쓰기 권한이 없어야 admission을 통과한다. Ghidra Bundle은 당시의 바이너리 해시와 exporter 해시를 포함한다.

## 다음 실험

[실험 순서와 통과 조건](NEXT_EXPERIMENT.md)의 Lua 입력 출처, 분기·함수 호출, 반환 경로를 조건부로 연결했다. Python·JavaScript의 첫 adapter와 분배 구간은 관측했다. 다음에는 새 두 언어의 값 계산 경로와 객체/Number 타입 분기를 [공통 전이 형식](COMMON_VM_TRANSITION_FORMAT.md)으로 연결하고, 설명하지 못한 호출·메모리·JOIN·동적 코드를 `unknown`으로 남긴다.
