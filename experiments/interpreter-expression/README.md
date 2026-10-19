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
| Python PyLong 할당 효과 | 동일한 구간 적용기로 캐시 밖 객체 생성 경로의 전체 네이티브 전이와 객체 필드를 확인 | 할당 경로 4건 일치·캐시 경로 1건 `unknown`; `Write`로 관측된 바이트 전이는 재현하지만 논리적 `Allocate`·freshness는 미증명 |
| Python 제한 풀 객체 수명 | 실제 CPython 호출의 범위 지정 allocator에서 네이티브 helper 요약과 수명 ledger 연결 | 2개 성공 경로 × 4슬롯 조건부 SMT 증명; 별도 입력 2개를 포함한 3회 실행에서 helper 30회·객체 15개 일치, 잘못된 수명 기록 13종 거부 |
| 공통 수명 효과 합성 | 언어 중립 `Allocate`·`Free`·`AllocationFailed` 상태를 네이티브 구간 전이와 연결 | 별도 입력 2개를 포함한 3회 실행에서 성공 helper 30회와 수명 효과 33개 합성; 부정 입력 18종 거부. 고갈 3건은 관측 효과로 유지 |
| 세 엔진 통합 경로·값 실험 | 분기·호출의 새 입력 `42`를 세 엔진에서 재증명하고 공통 값 슬라이스·제한된 IL로 투영 | Python·JavaScript 저장 숫자 구간 각 1건 일치, Lua는 새 경로 재증명. 문자열 2·6자리 요약 일치, 12자리 `unknown`; Lua 제한 풀 실패·GC·새 시도 관측 |
| 공통 AST-IL·새 경로 연구 | 네이티브 전이 AST의 typed IL 변환, 주소·제어 의존성 감사, JS 12~18자리 요약, Lua allocator 실패·재시도 수명 효과, CPython 예외 절단점 | 270개 식 루트 동등성 확인; JS 새 입력 3건·Lua 새 입력 2건 적용. Python 예외는 2건의 절단점 관측이며 오류 전파 구간은 미증명 |
| 관측 분배 경계·의존성 재검사 | 간접 분배 사이에서 기존 숫자 전이에 맞는 구간을 자동 탐색하고 `cmov`의 실제 P-code 경로를 확인 | Python·JavaScript의 새 입력 `43` 각 1구간 적용, Python `252`는 `unknown`. JavaScript 전체 호출자에는 미지원 내부 흐름 등 4,228건이 남음 |
| 세 엔진 공통 숫자 값 IL | Lua·Python·JavaScript의 서로 다른 결과 표현을 decode하고 같은 3노드 `BV32 X+5` 값 IL로 조건부 refinement | 각 엔진의 저장된 P-code 경로에서 공통 영역 `5..251`의 값 관계를 SMT로 확인. 새 Lua `42`, Python·JavaScript `43` 일치; 전체 네이티브 효과는 별도 계약으로 유지 |
| 공통 프로그램 표현 IL | Python의 전체 관측 경로 4개와 Lua·JavaScript의 개별 핸들러 구간을 같은 노드·증거·미해결 의무 형식으로 기록 | Python 4경로의 계산된 상태·바이트 메모리 연결, Lua·JavaScript 각 1구간 재적용; 변조 12종 거부. 전체 프로그램 복원 또는 네이티브 JSON 독립 실행은 아직 아님 |

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

[Python 할당 효과 결과](PYTHON_ALLOCATION_EFFECT_RESULT.md)는 같은 적용기로 PyLong 새 객체 경로의 읽기 42개·쓰기 18개와 결과 객체 필드를 재현한다. 기존 주소의 바이트를 먼저 읽는 추적도 확인했으므로, 네이티브 `Write`와 논리적 `Allocate`·객체 수명 증명을 구분한다.

[Python 제한 풀 수명 결과](PYTHON_POOL_LIFETIME_RESULT.md)는 CPython 객체 도메인 allocator의 명시된 4슬롯 풀에서 생성·해제·주소 재사용·고갈을 기록했다. 풀 상태 helper의 전체 메모리 전이를 조건부로 증명하고, 관측된 `PyLong` 객체를 세대별 수명 ledger에 연결했다. 일반 CPython 힙의 소유권 증명까지 확장된 결과는 아니다.

[공통 수명 효과 결과](COMMON_LIFETIME_EFFECT_RESULT.md)는 별도 풀 ledger의 자원 정체성·범위·세대 규칙을 공통 코어로 옮겼다. 고정 네이티브 구간의 효과를 helper 반환 시점에 합성하고 새 입력에도 적용했다. `AllocationFailed`는 성공 helper 증명을 재사용하지 않는 관측 효과로 남겼다.

[Lua 공통 수명 효과 결과](LUA_POOL_COMMON_LIFETIME_RESULT.md)는 같은 코어를 Lua 5.4.8의 긴 문자열 allocator 호출과 GC 해제에 연결했다. 고정 Lua ELF의 네이티브 helper를 별도로 증명하고 두 새 입력에 요약을 적용했다.

[세 엔진 통합 실험 결과](INTEGRATED_PIPELINE_RESULT.md)는 저장된 경로 증명·숫자 구간 요약·공통 값 슬라이스·제한된 값 IL을 한 실행기로 묶었다. Lua allocator 실패와 길이 경계의 `unknown`도 별도 근거로 보존했다. 아직 자동 P-code/SSA→IL 생성은 아니다.

[다음 연구 단위 결과](NEXT_RESEARCH_UNIT_RESULT.md)는 저장된 네이티브 SMT AST를 공통 typed IL로 옮겨 270개 루트의 동등성을 확인했다. 긴 JavaScript 문자열 경로와 Lua 실패·재시도 allocator 경로를 별도 새 입력에 적용했다. CPython의 예외 접점은 관측했고 그 사이의 오류 전파는 미요약으로 남겼다.

[분배 경계·의존성 감사 결과](BOUNDARY_DEPENDENCY_RESULT.md)는 고정 PC 없이 간접 분배 사이의 후보를 찾고 기존 전체 전이로 승인한 결과를 기록한다. `cmov` 내부에서 실제로 실행된 P-code만 고르는 검사와 미지원 JavaScript 흐름의 남은 의무도 구분한다.

[공통 숫자 IL refinement 결과](COMMON_NUMERIC_REFINEMENT_RESULT.md)는 세 엔진의 값 계산을 작은 typed IL로 분리하고, Python 객체·JavaScript Smi·Lua payload의 연결 및 원래 네이티브 효과 계약을 별도로 검증한다. 이 IL은 숫자 결과의 축약이며 전체 실행의 효과 삭제 증명은 아니다.

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
- `freeze_python_allocated_segment.py`, `apply_python_allocated_segment.py`: 기존 Python 할당 P-code 요약을 공통 구간 형식으로 동결·적용하고 객체 필드·캐시 경로·할당 의미의 한계를 확인한다. [할당 효과 결과](PYTHON_ALLOCATION_EFFECT_RESULT.md)에 근거가 있다.
- `verify_python_composed_core.py`: 원래 진입 상태를 고정한 공통 코어 변조 9종과 FS 상대 읽기를 포함한 Python 두 구간 연결을 확인한다.
- `python_pool_lifetime_fixture.c`, `trace_python_pool_lifetime.py`, `freeze_pool_lifetime.py`, `pool_lifetime_ledger.py`, `apply_pool_lifetime.py`: 실제 CPython의 제한된 객체 풀 trace, 네이티브 수명 helper 증명, 별도 입력 적용. [수명 결과](PYTHON_POOL_LIFETIME_RESULT.md)에 증거와 재현 순서가 있다.
- `common_lifetime_effects.py`, `apply_common_pool_effects.py`: 주소 공간·domain·자원·generation으로 정의한 공통 수명 효과와 네이티브 구간 합성 검증. [공통 수명 결과](COMMON_LIFETIME_EFFECT_RESULT.md)에 적용 조건과 한계가 있다.
- `lua_pool_lifetime_fixture.c`, `trace_lua_pool_lifetime.py`, `freeze_lua_pool_lifetime.py`, `apply_lua_pool_effects.py`: 실제 Lua allocator 호출의 제한 풀 수명 효과와 GC 해제·주소 재사용 검증. [Lua 공통 수명 결과](LUA_POOL_COMMON_LIFETIME_RESULT.md)에 재현 순서가 있다.
- `common_native_slice.py`, `run_integrated_pipeline.py`, `integrated_case.*`, `integrated_lua_runner.c`, `lua_pool_failure_retry_fixture.c`: 새 세 엔진 경로의 값 후보 선택·증명서 기반 IL·평가 oracle·제어된 Lua 실패/재시도. [통합 결과](INTEGRATED_PIPELINE_RESULT.md)에 범위와 재현 순서가 있다.
- `native_ast_il.py`, `analyze_dependency_slice.py`, `freeze_js_long_string.py`, `apply_js_long_string.py`, `trace_lua_allocator_failure.py`, `freeze_lua_allocator_paths.py`, `apply_lua_allocator_paths.py`, `probe_python_exception_boundary.py`: 공통 전이 IL, 주소·제어 의무, 새 JS/Lua 경로와 Python 예외 접점을 기록한다. [다음 연구 단위](NEXT_RESEARCH_UNIT_RESULT.md)에 증거 경계와 재현 순서가 있다.
- `discover_dispatch_intervals.py`, `observed_pcode_schedule.py`, `audit_observed_dependencies.py`: 관측 분배 후보의 검색·전이 승인, `cmov` 명령 내부 실행 경로, 세 엔진 의존성 기록. [분배 경계·의존성 감사](BOUNDARY_DEPENDENCY_RESULT.md)에 범위와 재현 순서가 있다.
- `probe_unseen_python_path.py`: 기존 할당 요약을 사용하지 않고 관측 Python 구간의 전체 네이티브 전이를 생성해 다른 입력에 적용한다. 이웃 분배 구간의 의미 미분류 재사용과 두 숫자 경로의 조건부 값 IL 공유를 [실험 결과](UNSEEN_PATH_FAMILY_PROBE_RESULT.md)에 기록했다.
- `probe_connected_python_program.py`: Python의 캐시·할당 숫자 경로와 다음 분배 구간을 계산된 상태·메모리로 순차 연결하고, 제어 edge의 미탐색 의무와 쓰기 보존형 표시를 [연결 결과](CONNECTED_PYTHON_PROGRAM_RESULT.md)에 기록했다.
- `probe_python_remaining_scope.py`: Python 할당 경로의 고정 환경 조건분기 반대쪽을 SMT로 검사하고 새 `251`·`254` 전체 추적으로 확인했다. 호출 인자와 바깥 반환 연결, allocator 수명의 미해결 의무는 [남은 범위 결과](PYTHON_REMAINING_SCOPE_RESULT.md)에 기록했다.
- `probe_connected_python_prefix.py`, `probe_python_prefix_branches.py`, `common_program_path_il.py`, `build_evidence_program_il.py`: Python 호출자 앞부분을 libc 벡터 호출 12명령만 남기고 연속 재생하며, 반대 분기 후보를 실제 추적과 대조한다. 세 전체 추적의 증거 포함 경로 IL과 미해결 의무 판정은 [경로 IL 설계](EVIDENCE_PROGRAM_IL_DESIGN.md)에 기록했다.
- `bounded_memset_contract.py`, `common_path_executor.py`, `apply_bounded_python_program.py`, `audit_python_branch_candidates.py`, `audit_python_lifetime_authority.py`: 고정 libc의 8바이트 0 채우기 경로를 조건부 계약으로 계산하고 Python의 4개 전체 경로에서 6구간을 연속 적용한다. 분기 후보의 실제 도달과 기본 allocator의 미승인 수명을 [계산 경로 결과](BOUNDED_PROGRAM_EXECUTION_RESULT.md)에 구분했다.
- `refine_common_numeric_il.py`: 세 엔진의 네이티브 값 AST에서 공통 덧셈 후보를 얻고 typed 값 IL에 대한 조건부 refinement, 원래 전이 효과, 새 입력 적용을 확인한다. [공통 숫자 IL 결과](COMMON_NUMERIC_REFINEMENT_RESULT.md)에 근거와 한계가 있다.
- `build_common_program_representation.py`: 선택된 Python 전체 관측 경로와 Lua·JavaScript 핸들러 구간을 하나의 표현 IL로 만든다. [공통 프로그램 표현 결과](COMMON_PROGRAM_REPRESENTATION_RESULT.md)에 적용 범위와 남은 전체 로직 복원 조건을 구분했다.

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

[공통 프로그램 표현 결과](COMMON_PROGRAM_REPRESENTATION_RESULT.md)를 출발점으로 다른 외부 호출 경로, 미탐색 분기·예외, allocator 수명 증거와 Lua·JavaScript의 경로 합성을 확장해야 한다. 현재의 공통 숫자 IL과 프로그램 표현 IL은 선택된 경로의 조건부 부분 로직이다.
