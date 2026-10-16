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
| [`tools/compare_analysis.py`](tools/compare_analysis.py) | 향후 분석기 결과를 `pass/fail/uncovered/accepted_unknown/not_run/partial`로 분류 |
| [`tools/import_current_lua_results.py`](tools/import_current_lua_results.py) | 기존 Lua 요약의 검증 기록을 이 채점 형식으로 연결. 범용 분석기 실행은 아님 |

분석기의 입력은 **빌드된 ELF, 바이트코드 파일, 입력값**이다. 소스, 매니페스트, expected JSON과 Python 오라클은 채점 쪽에 둔다. 실행 시 입력은 64비트 signed 정수이고 VM payload 연산은 64비트 래핑이다. `.r4vm`은 8바이트 헤더 뒤에 opcode·목적 슬롯·출처 슬롯·signed 8비트 즉시값을 1바이트씩 둔다. 숫자 opcode 의미는 분석기 사전 규칙으로 제공하지 않는다.

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

현재 비교기는 **샘플별 결과와 효과**를 채점한다. guard의 전체 적용 범위, 동일 handler 요약 ID의 재사용, 보존 영역의 증명, 분석 비용은 아직 자동 채점하지 않는다. `expected_features`는 다음 분석 단계의 판정 항목이며, 이 칸이 있다고 해서 해당 기능을 검증했다고 세지 않는다.

## 실행

Linux x86-64에서 Python 3과 C 컴파일러가 필요하다. R4interpreter 저장소 루트에서:

```bash
cd experiments/vm-transition-testbed
python3 tools/build_cases.py
python3 tools/build_cases.py --check
python3 tools/run_fixtures.py
python3 tools/import_current_lua_results.py
python3 tools/compare_analysis.py reports/current-lua-analysis.json --output reports/current-lua-grade.json
```

현재 생성한 사례는 **15개, 입력 39개**다. C fixture와 Python 오라클/사람이 적은 핵심 출력의 대조는 39/39 일치했다. 기존 Lua 경로 요약을 변환해 채점하면 Lua 출력 9/9가 통과하며 그중 **holdout 7건**이다. 작은 VM의 30개 입력은 아직 분석기가 실행되지 않아 `not_run`이다. 이것을 분석 성공으로 합산하지 않는다.

새 분석기는 [`examples/analysis-results.example.json`](examples/analysis-results.example.json) 형태로 케이스별 `id`, `input`, `status`를 출력한다. `computed`이면 `result`를 문자열로 적고, 작은 VM 사례에는 `pc`와 `writes`도 넣는다. `unknown`은 `reason`이 필요하다. 예제 파일을 채점하면 `pass 1`, `accepted_unknown 1`, `not_run 37`이 나온다.

## 다음 분석 단계

이 테스트베드는 정답과 검증 입력을 준비한 상태다. 다음에는 `r4vm`의 Ghidra Low P-code Bundle을 만든 뒤, **명령 읽기·분배 경계를 찾는 코드와 경로 요약 생성기를 Lua 고정 주소 없이** 구현한다. VMT001–008에서 구조·연산·메모리 효과를 순서대로 채점하고, VMT009–012에서 섣부른 숫자 결과를 막는지 본다. 이후 같은 코어를 Lua VMT013–015에 적용한다. 컴파일 최적화 수준과 다른 인터프리터 언어는 분석 코어가 이 첫 행렬을 처리한 다음 추가한다.
