# Lua 인터프리터 계산식 실험

[실험 계획과 판정 기준](interpreter_expression_experiment_plan.md). `daasdmlkas` 기준 커밋은 `3a274f93d455d3caaebf72365e64820770341787`이며, 이 저장소는 그 프로젝트의 코드를 복사하거나 수정하지 않는다.

## 현재 결과

| 대상 | 분석 결과 | 확인 범위 |
|---|---|---|
| 합성 P-code | 8비트 `x+7`, `7-x`, `x+7-3` 식 투영 | 각 256개 입력, SMT 및 오류 주입 |
| 작은 실제 ELF | 64비트 `x+7` 식 투영 | ELF 직접 실행 137개 입력, 사양과 SMT 비교 |
| Lua 5.4.8 실행기 | 정적 슬라이스에는 미해결 의존 4개·6개 | 바이트코드 실행 135개 입력; 분석기가 식을 복원한 것은 아님 |

Lua의 `luaV_execute`는 Ghidra Bundle에서 정규화되지만 3,670개 명령, 1,608개 SSA JOIN, 442개 미해결 읽기 노드를 가진다. [루트 결과](lua_root_probe_result.json), [VM 결과](lua_vm_probe_result.json), [Bundle 전체 기록](lua_bundle_stats.json)을 구분해서 읽어야 한다. 전체 기록은 61번째 함수의 관측 범위 오류로 중단됐다.

[첫 실제 실행 추적](FIRST_TRACE_RESULT.md)에서는 입력 `9`의 Lua VM 내부 덧셈 `9 + 7 = 16`을 P-code `INT_ADD`와 대조했다. 이것은 한 경로의 관측 결과이며 아직 입력에 대한 일반식은 아니다.

## 파일

- `expression_probe.py`, `elf_expression_probe.py`, `lua_root_probe.py`, `lua_vm_probe.py`: 분석 코드와 대응하는 `*_result.json`.
- `elf_expression_fixture.c`, `lua_interpreter_fixture.c`: 네이티브 입력 프로그램. 같은 이름의 확장자 없는 파일은 당시 빌드한 ELF이다.
- `lua_chunk_source.lua`: 평가용 원본. 분석 입력은 디버그 정보를 제거한 `lua_chunk.luac`이다. `lua_compile_chunk.c`는 바이트코드 생성 도구다.
- `artifacts/elf_bundle.tar.gz`, `artifacts/lua_bundle.tar.gz`: admission 가능한 Ghidra 12.0.4 Bundle. [SHA-256 목록](artifacts/SHA256SUMS)에 아카이브 해시를 기록했다. JSON 결과의 `/workspace/scratch` 경로는 원래 실험 당시 경로다.
- `ptrace_instruction_trace.c`, `trace_bundle_compare.py`: 첫 명령 단위 추적 및 Bundle 대조 도구. 원시 CSV와 요약 JSON은 [첫 추적 기록](FIRST_TRACE_RESULT.md)에 연결했다.

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

[구체적인 순서와 통과 조건](NEXT_EXPERIMENT.md): 같은 Lua 바이트코드에서 실제 실행 경로를 기록하고, 각 명령을 Bundle의 P-code에 대응시킨다. 연결하지 못한 호출·메모리·JOIN은 `unknown`으로 남긴다.
