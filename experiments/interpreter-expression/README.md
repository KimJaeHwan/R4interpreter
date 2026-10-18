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
| Python 3.13·JavaScript Ignition 첫 교차 실험 | 양쪽의 bytecode fetch→native handler 분배를 실제 주소로 연결하고 같은 guard/식 적용기에 연결 | 각 2개 native 분기 경로, 14개 출력 차등 검증. 이 초기 결과의 값 식은 표본 기반 후보이며 아래 후속 실험에서 범위를 좁혀 증명 |
| Python·JavaScript 값 요약 재사용 | JavaScript `AddSmi` 앞부분의 조건부 상태 요약과 Python cached PyLong 숫자 요약을 다른 입력에 적용 | 새 프로그램에서 엔진당 3건: 2건 정확 적용·1건 `unknown`·불일치 0건. 전체 핸들러 효과는 미완성 |
| 세 엔진의 관측 구간 전체 전이 | Lua·Python·JavaScript의 고정 경로를 같은 식·효과 형식으로 저장하고 공통 적용기로 평가 | 9개 대상 중 8개 일치·1개 `unknown`; 대상 P-code 재생 0회. Python 쓰기 12개와 JS 두 `AddSmi` 경로의 쓰기·후속 핸들러 포함 |
| Python 할당·JavaScript 문자열 경로 | 두 새 전체 네이티브 경로를 공통 형식에 추가하고 내부 값 구간을 SMT로 투영 | 합계 14개 대상 중 12개 일치·2개 `unknown`; Python `X+5` 객체 digit과 JS `"두 자리 숫자" + 5`의 출력 문자 확인. BigInt 오류는 미해결 |
| JavaScript 문자열 길이별 경로 | 한·세·네 자리의 전체 전이를 추가하고, 한 자리부터 다섯 자리까지 공통 문자 복사를 P-code로 확인 | 합계 23개 대상 중 21개 일치·2개 `unknown`; 문자 복사 15곳·끝 문자 5곳과 기호 주소를 가진 두 문자 복사 블록을 증명. 다섯 자리 전체 전이는 `unknown` |
| JavaScript 문자열 복사 루프 합성 | 세·네 자리의 공통 앞·뒤 구간과 두 문자 반복 구간을 기호 전이로 저장해 조합 | 길이 2~11의 10건에서 전체 네이티브 전이 일치; 12~16의 5건은 다른 경로라 `unknown`. 저장된 요약 적용 시 P-code 재생 0회 |
| JavaScript·Lua 공통 구간 합성 | 문자열 루프 평가 코어를 분리하고 Lua 숫자 핸들러→fetch/decode/dispatch→핸들러에도 적용 | JavaScript 10건 일치·5건 `unknown` 유지; Lua 6개 입력에서 각 51개 명령의 상태·읽기·쓰기가 일치. 적용 시 P-code 재생 0회 |

Lua의 `luaV_execute`는 Ghidra Bundle에서 정규화되지만 3,670개 명령, 1,608개 SSA JOIN, 442개 미해결 읽기 노드를 가진다. [루트 결과](lua_root_probe_result.json), [VM 결과](lua_vm_probe_result.json), [Bundle 전체 기록](lua_bundle_stats.json)을 구분해서 읽어야 한다. 전체 기록은 61번째 함수의 관측 범위 오류로 중단됐다.

[첫 실제 실행 추적](FIRST_TRACE_RESULT.md)에서는 입력 `9`의 Lua VM 내부 덧셈 `9 + 7 = 16`을 P-code `INT_ADD`와 대조했다. 이것은 한 경로의 관측 결과이며 아직 입력에 대한 일반식은 아니다.

[바이트코드→네이티브 처리 구간 대응](BYTECODE_HANDLER_RESULT.md)에서는 입력 `9`, `0`의 실행 기록을 대조했다. 실행된 바이트코드 인덱스 `0, 1, 2, 4`가 두 입력에서 같은 네이티브 진입 주소로 분기했고, 인덱스 `2`의 구간에 실제 덧셈이 있었다.

[입력 출처·P-code 계산식·적용 범위](INPUT_PROVENANCE_RESULT.md)에서는 실행기 인자에서 VM 피연산자까지 실제 메모리 주소를 연결했다. 선택한 경로의 식은 `signed64((X+7) mod 2^64)`이며, 별도 입력 6개와 정수 경계값에서 같은 VM 경로와 출력을 확인했다. 다른 경로는 아직 `unknown`이다.

[첫 공통 전이 요약 결과](TRANSITION_SUMMARY_RESULT.md)에서는 `x+7`에서 만든 조건부 상태 전이를 `x+11`의 같은 처리 구간에 재추출 없이 적용했다. 작은 네이티브 ELF도 같은 JSON 구조와 적용기를 사용한다. 이것은 한 경로의 차등 검증 결과이며 전체 Lua handler나 다른 언어의 분석 결과는 아니다.

[두 handler 합성 결과](TWO_HANDLER_COMPOSITION_RESULT.md)에서는 명령 위치와 VM 슬롯이 다른 `x+7; +11` 바이트코드에 기존 요약을 적용하고, 그 사이 fetch/decode/dispatch를 P-code로 연결했다. 첫 처리 구간의 출력과 바이트코드·읽기 전용 점프 테이블에서 두 번째 진입 상태를 예측했다.

[입력 수준 식 축약 결과](../vm-transition-testbed/results/LOGIC_PROJECTION_RESULT.md)에서는 두 엔진의 요약을 같은 `logic_projection.py`로 합성하고 SMT 동치 확인 후 긴 P-code 식을 간단한 `X` 식으로 줄였다. Lua의 축약 범위는 현재 마지막 숫자 핸들러까지이며 최종 반환 경로는 포함하지 않는다.

[Lua 분기·함수 호출 실험](LUA_BRANCH_CALL_RESULT.md)은 호출 전후 두 바이트코드 코드 영역을 실제 추적으로 연결했다. 네이티브 P-code 재생으로 VM 입력의 분기·호출·덧셈 결과와 Lua 반환 경로를 연결했다. [Python·JavaScript 적용 직전 정리](LUA_PRE_PYTHON_JS_READINESS.md)는 여섯 입력의 조건부 증명, 다른 세 Lua 바이트코드의 22개 차등 검증, 새 경로의 `unknown` 판정을 구분한다.

[Python·JavaScript 첫 교차 결과](PYTHON_JS_FIRST_RESULT.md)는 CPython 3.13.5와 Node 24.19.0 Ignition의 실제 bytecode→native dispatch 대응, 공통 값 sort 형식, 14개 출력 검증을 기록한다. 후속 [전체 함수 경로 결과](PYTHON_JS_FULL_FLOW_RESULT.md)는 제한된 VM 입력 상태에서 분기·호출·덧셈·반환을 P-code와 하드웨어 감시점으로 연결한다. 기존 portable 적용기의 새 CLI 입력은 계속 `unknown`으로 둔다.

[값 요약 재사용 실험](SUMMARY_REUSE_EXPERIMENT.md)은 호출 결과에서 역방향 의존성을 찾고, 관측된 JavaScript 핸들러 경계를 선택한 뒤, Python·JavaScript 값 요약을 다른 실행에 적용한 이전 단계다. 후속 [세 엔진 관측 전이 결과](THREE_ENGINE_NATIVE_TRANSITION_RESULT.md)는 Python의 12개 네이티브 쓰기와 JavaScript 핸들러의 다음 분배까지 포함하고, Lua·Python·JavaScript에 같은 평가 코어를 사용한다. 다른 타입·경로는 `unknown`으로 남는다.

[할당·문자열 경로와 값 축약 결과](EXPANDED_PATH_VALUE_PROJECTION_RESULT.md)는 Python의 새 PyLong 할당 경로와 JavaScript의 문자열 연결 경로를 추가했다. 전체 네이티브 전이의 모든 모델링한 효과를 저장한 상태에서, 결과값만 `X+5`와 ASCII 문자 복사·`'5'`로 투영한 증거와 남은 한계를 구분한다.

[문자열 길이별 결과](JS_STRING_LENGTH_FAMILY_RESULT.md)는 JavaScript의 한·두·세·네 자리 문자열에 서로 다른 전체 경로 요약을 적용하고, 다섯 자리까지 반복되는 문자 복사를 공통 P-code 값 규칙으로 확인한다. 다섯 자리의 전체 상태 전이는 `unknown`으로 유지한다.

[문자열 루프 합성 결과](JS_STRING_LOOP_COMPOSITION_RESULT.md)는 후속 실험이다. 다섯 자리의 전체 전이까지 포함해 길이 2~11에서 10건을 확인했다. 재사용 가능한 다섯 구간의 SMT 식을 저장했고, 대상 추적에 적용할 때 소스·대상 P-code를 다시 재생하지 않았다. 12자리 이상의 다른 경로는 `unknown`이다.

[공통 구간 합성 결과](CROSS_ENGINE_SEGMENT_COMPOSITION_RESULT.md)는 같은 guard·상태·읽기·쓰기·후속 주소 적용기를 Lua의 숫자 핸들러와 분배 구간에도 사용했다. 첫 핸들러의 계산된 출력을 두 번째 진입까지 전달하고 6개 입력의 51개 명령 전이를 확인했다. 경계와 바이트코드 바인딩은 아직 대상별 어댑터가 제공한다.

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
- `slice_js_caller_result.py`, `discover_js_boundaries.py`, `slice_js_summary_reuse.py`, `prove_js_summary_reuse.py`, `prove_python_value_reuse.py`, `evaluate_summary_applicability.py`, `evaluate_holdout_programs.py`: 결과에서의 역방향 선택, 관측 경계, 조건부 요약 재사용과 새 프로그램 평가. [값 요약 재사용 결과](SUMMARY_REUSE_EXPERIMENT.md)에 근거와 한계를 기록했다.
- `prove_js_handler_transition.py`, `prove_python_handler_transition.py`, `evaluate_alternate_paths.py`, `common_observed_transition.py`: 전체 관측 구간의 상태·효과 요약, 대체 경로 거부, 세 엔진 공통 적용기. [이번 결과](THREE_ENGINE_NATIVE_TRANSITION_RESULT.md)에 재현법과 한계를 기록했다.
- `build_expanded_native_paths.py`, `project_expanded_values.py`: Python 할당·JavaScript 문자열의 전체 경로 요약과 내부 결과값 증명. [후속 결과](EXPANDED_PATH_VALUE_PROJECTION_RESULT.md)에 범위를 기록했다.
- `prove_js_string_copy_family.py`: JavaScript 문자열 길이 1~5에서 반복되는 바이트 복사 규칙과 최종 출력 바이트를 확인한다. [길이별 결과](JS_STRING_LENGTH_FAMILY_RESULT.md)에 전체 전이와 값 투영의 범위를 나눠 기록했다.
- `compose_js_string_loop.py`, `freeze_js_string_loop.py`, `apply_js_string_loop_summary.py`: 두 문자 루프의 guard·효과 증명, 다섯 구간 전이 요약 생성, 저장된 요약의 대상 추적 적용. [루프 합성 결과](JS_STRING_LOOP_COMPOSITION_RESULT.md)에 증거와 한계를 기록했다.
- `composed_native_transition.py`, `freeze_lua_handler_bridge_segments.py`, `apply_lua_handler_bridge_summary.py`: JavaScript·Lua가 공유하는 구간 평가 코어와 Lua 핸들러·분배 구간의 동결·합성. [공통 구간 결과](CROSS_ENGINE_SEGMENT_COMPOSITION_RESULT.md)에 재현법을 기록했다.

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

[공통 구간 결과](CROSS_ENGINE_SEGMENT_COMPOSITION_RESULT.md)의 다음 연구 순서는 Python 객체 할당 또는 예외의 효과 표현, 12자리 이상에서 바뀌는 JavaScript 앞 경로, BigInt 오류의 실제 Throw 경계 확보, 경계·live-in/out 자동화, alias·생존성에 근거한 안전한 상태 축약과 [공통 전이 형식](COMMON_VM_TRANSITION_FORMAT.md) 확장이다.
