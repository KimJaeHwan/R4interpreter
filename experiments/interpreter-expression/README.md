# Lua 인터프리터 계산식 실험

[실험 계획과 판정 기준](interpreter_expression_experiment_plan.md). `daasdmlkas` 기준 커밋은 `3a274f93d455d3caaebf72365e64820770341787`이며, 이 저장소는 그 프로젝트의 코드를 복사하거나 수정하지 않는다.

## 현재 결과

| 대상 | 분석 결과 | 확인 범위 |
|---|---|---|
| 합성 P-code | 8비트 `x+7`, `7-x`, `x+7-3` 식 투영 | 각 256개 입력, SMT 및 오류 주입 |
| 작은 실제 ELF | 64비트 `x+7` 식 투영 | ELF 직접 실행 137개 입력, 사양과 SMT 비교 |
| Lua 5.4.8 실행기 | 정적 슬라이스에는 미해결 의존 4개·6개; 관측 경로의 P-code 재생으로 `(X+7) mod 2^64` 도출 | 첫 VM 호출의 동적 경로, 별도 입력 6개와 경계값 확인 |

Lua의 `luaV_execute`는 Ghidra Bundle에서 정규화되지만 3,670개 명령, 1,608개 SSA JOIN, 442개 미해결 읽기 노드를 가진다. [루트 결과](lua_root_probe_result.json), [VM 결과](lua_vm_probe_result.json), [Bundle 전체 기록](lua_bundle_stats.json)을 구분해서 읽어야 한다. 전체 기록은 61번째 함수의 관측 범위 오류로 중단됐다.

[첫 실제 실행 추적](FIRST_TRACE_RESULT.md)에서는 입력 `9`의 Lua VM 내부 덧셈 `9 + 7 = 16`을 P-code `INT_ADD`와 대조했다. 이것은 한 경로의 관측 결과이며 아직 입력에 대한 일반식은 아니다.

[바이트코드→네이티브 처리 구간 대응](BYTECODE_HANDLER_RESULT.md)에서는 입력 `9`, `0`의 실행 기록을 대조했다. 실행된 바이트코드 인덱스 `0, 1, 2, 4`가 두 입력에서 같은 네이티브 진입 주소로 분기했고, 인덱스 `2`의 구간에 실제 덧셈이 있었다.

[입력 출처·P-code 계산식·적용 범위](INPUT_PROVENANCE_RESULT.md)에서는 실행기 인자에서 VM 피연산자까지 실제 메모리 주소를 연결했다. 선택한 경로의 식은 `signed64((X+7) mod 2^64)`이며, 별도 입력 6개와 정수 경계값에서 같은 VM 경로와 출력을 확인했다. 다른 경로는 아직 `unknown`이다.

## 파일

- `expression_probe.py`, `elf_expression_probe.py`, `lua_root_probe.py`, `lua_vm_probe.py`: 분석 코드와 대응하는 `*_result.json`.
- `elf_expression_fixture.c`, `lua_interpreter_fixture.c`: 네이티브 입력 프로그램. 같은 이름의 확장자 없는 파일은 당시 빌드한 ELF이다.
- `lua_chunk_source.lua`: 평가용 원본. 분석 입력은 디버그 정보를 제거한 `lua_chunk.luac`이다. `lua_compile_chunk.c`는 바이트코드 생성 도구다.
- `artifacts/elf_bundle.tar.gz`, `artifacts/lua_bundle.tar.gz`: admission 가능한 Ghidra 12.0.4 Bundle. [SHA-256 목록](artifacts/SHA256SUMS)에 아카이브 해시를 기록했다. JSON 결과의 `/workspace/scratch` 경로는 원래 실험 당시 경로다.
- `ptrace_instruction_trace.c`, `trace_bundle_compare.py`: 첫 명령 단위 추적 및 Bundle 대조 도구. 원시 CSV와 요약 JSON은 [첫 추적 기록](FIRST_TRACE_RESULT.md)에 연결했다.
- `bytecode_handler_map.py`: 바이트코드 명령 읽기와 VM 간접 분기를 원시 추적·Bundle에 대조한다. 결과와 적용 범위는 [바이트코드 대응 기록](BYTECODE_HANDLER_RESULT.md)에 있다.
- `trace_input_provenance.py`, `replay_input_path.py`, `guard_scope_probe.py`: 입력 메모리 출처 추적, 선택된 P-code 경로 재생, 별도 입력과 경로 비교. 결과와 재현법은 [입력 출처 결과](INPUT_PROVENANCE_RESULT.md)에 있다.

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

[실험 순서와 통과 조건](NEXT_EXPERIMENT.md)의 입력 출처, 선택 경로 계산식, 별도 입력 판정은 완료했다. 다음에는 다른 바이트코드로 같은 방식의 재사용성을 확인한다. 연결하지 못한 호출·메모리·JOIN은 `unknown`으로 남긴다.
