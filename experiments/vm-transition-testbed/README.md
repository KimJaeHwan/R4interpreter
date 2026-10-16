# VM 전이 요약 테스트베드

목표는 Lua의 ADD 사례를 더 손으로 늘리는 대신, **같은 P-code 분석 엔진이 서로 다른 명령·경로를 요약할 수 있는지** 측정하는 것이다. [`tdo_testbed`](https://github.com/KimJaeHwan/tdo_testbed)의 `0966d8cce426889e1b8677b30edce6ebeebfe748`에서 매니페스트·실행 fixture·별도 expected JSON·채점기의 분리 방식을 참고했다. 해당 저장소의 코드는 복사하거나 수정하지 않았다.

## 구성

| 파일 | 역할 |
|---|---|
| [`manifests/cases.json`](manifests/cases.json) | 케이스 ID, 프로그램, 입력, 사람이 지정한 핵심 출력 정답의 단일 원본 |
| [`fixtures/r4vm.c`](fixtures/r4vm.c) | 4바이트 명령과 4개 VM 슬롯을 가진 작은 네이티브 인터프리터 |
| [`tools/build_cases.py`](tools/build_cases.py) | 매니페스트 검증, `.r4vm` 생성, 독립 Python 실행 오라클로 세부 효과/PC 계산, C fixture 빌드 |
| [`expected/cases.expected.json`](expected/cases.expected.json) | 생성된 채점 정답. 분석기 입력에서 제외 |
| [`tools/run_fixtures.py`](tools/run_fixtures.py) | 실제 C ELF와 기존 Lua 실행기의 동작을 정답과 대조 |
| [`tools/compare_analysis.py`](tools/compare_analysis.py) | 분석기 결과를 `pass/fail/uncovered/accepted_unknown/not_run/partial`로 분류 |
| [`tools/import_current_lua_results.py`](tools/import_current_lua_results.py) | 기존 Lua 요약의 검증 기록을 이 채점 형식으로 연결. 범용 분석기 실행은 아님 |
| [`tools/capture_native_paths.py`](tools/capture_native_paths.py), [`tools/train_r4vm.py`](tools/train_r4vm.py) | ELF의 실행 경로를 Ghidra Low P-code로 재생해 조건부 전이 요약 11개를 동결 |
| [`tools/analyze_r4vm.py`](tools/analyze_r4vm.py) | 동결한 요약을 새 바이트코드·입력에 적용. opcode 의미표, 매니페스트 정답, 런타임 실행을 사용하지 않음 |
| [`tools/run_logic_projection.py`](tools/run_logic_projection.py) | R4VM 전체 프로그램과 보관된 Lua 핸들러·두 핸들러 연결 경로를 공통 P-code 투영기로 `X`의 조건부 식으로 축약 |
| [`tools/compare_logic_projection.py`](tools/compare_logic_projection.py) | 축약된 식을 별도 R4VM 정답 입력에 대입해 결과·PC·순서 있는 쓰기 평가 |
| [`tools/restore_frozen_binary.py`](tools/restore_frozen_binary.py) | Bundle에서 해시가 일치하는 ELF를 복원해 동일한 요약을 바로 적용 |
| [`results/ANALYSIS_RESULT.md`](results/ANALYSIS_RESULT.md) | 실제 분석 결과와 남은 한계 |
| [`results/LOGIC_PROJECTION_RESULT.md`](results/LOGIC_PROJECTION_RESULT.md) | 원본 스크립트에 가까운 입력 수준 식으로 축약한 결과와 적용 범위 |

분석기 적용 입력은 **빌드된 ELF, 동결한 P-code 경로 요약, 바이트코드 파일, 입력값**이다. 소스, 매니페스트, expected JSON과 Python 오라클은 채점 쪽에 둔다. 실행 시 입력은 64비트 signed 정수이고 VM payload 연산은 64비트 래핑이다. `.r4vm`은 8바이트 헤더 뒤에 opcode·목적 슬롯·출처 슬롯·signed 8비트 즉시값을 1바이트씩 둔다. 숫자 opcode 의미는 분석기 사전 규칙으로 제공하지 않는다.

## 케이스

| ID | 판별할 실패·기능 | 정책 |
|---|---|---|
| VMT001–002 | 같은 handler, 다른 즉시값과 정수 래핑 | 계산 요구 |
| VMT003–004 | 슬롯 이동, 중간 쓰기 뒤 읽기, 두 명령 합성 | 계산 요구 |
| VMT005–006 | 뺄셈 피연산자 순서, XOR과 ADD 혼동 방지 | 계산 요구 |
| VMT007 | 분기 양방향과 서로 다른 쓰기 | 계산 요구 |
| VMT008 | 같은 슬롯에 순서 있는 두 쓰기와 별칭 | 계산 요구 |
| VMT009 | 정수 태그 조건 불일치 | `unknown` 또는 실제 타입 오류 허용 |
| VMT010–012 | 미모델링 호출, 잘못된 분배, 루프 | 근거 있는 `unknown` 허용 |
| VMT013–015 | 실제 Lua `x+7`, `x+11`, 두 덧셈 합성 | 출력 계산 요구 |

`compute` 정책의 사례에서 `unknown`은 **미달 범위**로 집계하며 성공으로 세지 않는다. `unknown_allowed` 사례는 원인을 적은 `unknown`을 허용한다. 런타임 오류 경로에서 숫자 결과를 만든다면 실패다. 작은 VM 사례의 `computed` 판정은 최종 숫자뿐 아니라 **다음 PC와 순서 있는 슬롯 쓰기 전체**가 같아야 통과한다. Lua 회귀 사례는 현재 추출 경계의 제약 때문에 출력만 채점한다. 매니페스트의 `seed`와 `holdout`을 나눠 미사용 입력 통과 수를 별도로 보고한다.

`writes.slot`은 테스트베드가 정답을 읽기 쉽게 만든 **채점용 상태 투영**이다. 공통 분석기의 내부 요약은 계속 네이티브 주소·폭·값·순서를 보존해야 한다. 이후 주소를 슬롯에 대응시키는 평가 adapter를 추가할 수 있으며, 이 투영을 분석기의 Lua/VM 공통 필수 필드로 삼지 않는다.

현재 비교기는 **샘플별 결과와 효과**를 채점한다. guard의 전체 적용 범위, 보존 영역의 증명, 분석 비용은 아직 자동 채점하지 않는다. `expected_features`는 별도 판정 항목이며, 이 칸이 있다고 해서 해당 기능을 검증했다고 세지 않는다. 분석 결과의 `path_ids`로 실제 요약 재사용은 확인할 수 있다.

## 원격 저장소를 받아 바로 채점

Python 3.11 이상이면 동결한 요약을 **Ghidra·C 컴파일러·`daasdmlkas` 없이** 적용할 수 있다. Linux/macOS 터미널 또는 Windows PowerShell에서 저장소를 받아 아래 순서로 실행한다. Windows에서는 `python3` 대신 `py -3`, `.venv/bin/python` 대신 `.venv\Scripts\python.exe`를 사용한다.

```bash
git clone https://github.com/KimJaeHwan/R4interpreter.git
cd R4interpreter/experiments/vm-transition-testbed
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-analysis.txt
.venv/bin/python tools/restore_frozen_binary.py
.venv/bin/python tools/run_r4vm_analysis.py
.venv/bin/python tools/import_current_lua_results.py
.venv/bin/python tools/combine_analysis.py reports/current-r4vm-analysis.json reports/current-lua-analysis.json --output reports/combined-analysis.json
.venv/bin/python tools/compare_analysis.py reports/combined-analysis.json --output reports/combined-grade.json
.venv/bin/python tools/run_logic_projection.py --output reports/input-logic-projection.json
.venv/bin/python tools/compare_logic_projection.py --projection reports/input-logic-projection.json --output reports/input-logic-grade.json
```

기존 `compare_analysis.py`의 정상 출력은 `pass: 37`, `accepted_unknown: 2`다. `VMT010`의 미모델링 helper 호출 2건이 `unknown`이며, Lua 9건은 기존 검증 기록을 합친 것이다. `build/r4vm`에 다른 컴파일러가 만든 ELF가 이미 있으면 복원기가 덮어쓰지 않는다. 요약과 일치하는 보관본으로 교체하려면 `.venv/bin/python tools/restore_frozen_binary.py --replace`를 사용한다. 분석 결과는 무시되는 `reports/`에 생성되므로 저장소 파일을 수정하지 않는다.

추가된 식 투영의 R4VM 채점 결과는 `pass: 28`, `accepted_unknown: 2`, `fail: 0`이다. Lua 보관 추적의 한 핸들러 `X+7`/`X+11`과 두 핸들러 연결 `X+18`도 같은 식 투영기를 사용한다. 축약 결과는 [별도 결과 문서](results/LOGIC_PROJECTION_RESULT.md)에 정리했다. Lua 함수의 최종 반환 경로까지 이번 투영으로 증명한 것은 아니다.

실제 C/Lua 실행기의 출력까지 다시 확인하려면 **Linux x86-64 또는 WSL2**에서 `python3 tools/run_fixtures.py`를 실행한다. 이는 실행 결과 정답 39/39를 확인하는 별도 단계다. Windows 네이티브/macOS에서는 ELF를 실행하는 이 단계가 지원되지 않는다.

## 테스트베드 생성과 실행

Linux x86-64에서 Python 3과 C 컴파일러가 필요하다. R4interpreter 저장소 루트에서:

```bash
cd experiments/vm-transition-testbed
python3 tools/build_cases.py
python3 tools/build_cases.py --check
python3 tools/run_fixtures.py
python3 tools/import_current_lua_results.py
python3 tools/compare_analysis.py reports/current-lua-analysis.json --output reports/current-lua-grade.json
```

현재 생성한 사례는 **15개, 입력 39개**다. C fixture와 Python 오라클/사람이 적은 핵심 출력의 대조는 39/39 일치했다. 작은 VM의 동결한 P-code 경로를 분석하면 **30개 중 28개 pass, 미모델링 호출 2개 accepted_unknown**이다. 기존 Lua 경로 요약은 별도로 9/9 pass였다. 둘을 합친 채점은 **37 pass, 2 accepted_unknown**이며, 훈련에 사용한 입력 3개를 제외한 holdout은 **34 pass, 2 accepted_unknown**이다. Lua 9건은 이번 새 분석기의 결과가 아니다.

새 분석기는 [`examples/analysis-results.example.json`](examples/analysis-results.example.json) 형태로 케이스별 `id`, `input`, `status`를 출력한다. `computed`이면 `result`를 문자열로 적고, 작은 VM 사례에는 `pc`와 `writes`도 넣는다. `unknown`은 `reason`이 필요하다. 예제 파일을 채점하면 `pass 1`, `accepted_unknown 1`, `not_run 37`이 나온다.

## P-code 경로 요약을 다시 추출할 때

이 단계는 Linux x86-64의 `ptrace`를 사용한다. Python 3.11 이상에서 [`requirements-analysis.txt`](requirements-analysis.txt)의 패키지가 필요하다. 기존 저장소의 `daasdmlkas` 체크아웃은 Bundle exporter를 읽기 전용으로 사용했으며, 분석 코드와 결과는 이 저장소에만 둔다. 현재 ELF와 일치하는 Ghidra 12.0.4 Bundle을 [`artifacts/r4vm_bundle.tar.gz`](artifacts/r4vm_bundle.tar.gz)에 보관했다. **동결 요약을 적용하는 데 재추출은 필요 없다.** 새 컴파일러/빌드의 ELF를 분석하려면 Bundle과 요약을 다시 생성해야 한다.

```bash
cd experiments/vm-transition-testbed
python3 tools/build_cases.py --check
python3 tools/train_r4vm.py
python3 tools/run_r4vm_analysis.py --output results/r4vm-analysis.json
python3 tools/import_current_lua_results.py
python3 tools/combine_analysis.py results/r4vm-analysis.json reports/current-lua-analysis.json
python3 tools/compare_analysis.py results/combined-analysis.json --output results/combined-grade.json
```

훈련 단계에서 네이티브 cutpoint `0x401410`은 이 ELF에 대한 수동 힌트다. 학습 추적은 `VMT001/003/005/006/009/011/012`의 입력 `5`, `VMT007`의 입력 `5`와 `0`에서 얻는다. `5`는 평가 샘플에 없고 `VMT007, 0`은 `seed`로 표시했다. 각 경로의 모든 방문 네이티브 명령을 Low P-code로 재생하고 레지스터·메모리 관측과 대조한 뒤, 경로 조건·순서 있는 효과·종료 레지스터 식을 저장한다. 실제 분석기는 동결한 요약과 ELF·바이트코드·입력만 사용하며, 평가 입력마다 추적하거나 요약을 다시 뽑지 않는다. 벤치마크 실행기만 매니페스트에서 평가 입력 목록을 읽는다.

분석기 출력 투영은 이 ELF의 루프 진입 상태와 `output` 함수의 호출 규약에 맞춘 adapter다. 여기에는 초기화된 VM 스택 스냅샷, 코드 버퍼 위치, `output` 인자와 write log 배치를 이용한다. 아직 루프 경계를 자동으로 발견하거나, 엔트리부터 출력까지의 전체 네이티브 경로를 증명하지 않았다.

## 다음 분석 단계

1. 고정 주소 cutpoint와 스택·출력 adapter를 P-code/SSA에서 추론하거나 근거 있는 사용자 힌트로 일반화한다.
2. 호출 요약을 붙여 VMT010을 계산하되, 미모델링 호출을 계속 `unknown`으로 처리한다.
3. guard 적용 범위, 별칭·frame 보존과 루프 종료를 정적으로 검증한다. 지금 37건의 일치는 지정한 샘플에 대한 차등 검증이다.
4. 새 R4VM 코어와 기존 Lua 적용기를 같은 추출·합성 경로로 묶은 뒤 Python과 JavaScript로 확장한다.
