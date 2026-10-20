# 전체 로직 복원: 제어 경로 작업 목록과 추가 조건 증명

이번 단계는 기존 720개 네이티브 분기·호출 [작업 목록](common_control_worklist_v1.json)을 발생 단위로 다시 읽어 [공통 frontier 지도](control_frontier_matrix_v1.json)를 만들었다. 이어서 Python 숫자 핸들러의 캐시 선택 조건을 [P-code/SMT로 증명](python_cache_branch_predicate_v1.json)하고, 앞서 증명한 Lua 조건과 함께 [진행 지도](control_frontier_progress_v1.json)에 연결했다. 지도는 전체 프로그램의 분기 수를 나타내지 않는다. 같은 VM 명령을 실행하는 네이티브 루프·캐시·할당기 분기도 포함된다.

## 720개 발생의 현재 상태

| 분류 | 발생 수 | 정확한 의미 |
| --- | ---: | --- |
| 반대 방향 관측, 같은 경계의 선행 네이티브 경로와 바이트코드 문맥 확인 | 6 | Python 숫자 캐시 경계 4개, Lua 분기 경계 2개 |
| 반대 방향 관측, 선행 네이티브 경로만 일치 | 5 | Lua 같은 네이티브 분기의 다른 입력 5개. 해당 실행의 바이트코드 fetch 위치는 직접 묶지 못함 |
| 고정된 소스 실행 상태·입력 범위에서 반대 방향 UNSAT | 91 | 해당 전제 안의 제한된 불가능성. 모든 VM 상태에서 불가능하다는 뜻은 아님 |
| 반대 방향 미해결 | 557 | 대응 추적이나 충분한 전제 증명이 없음 |
| 정상 복귀 관측, 예외 경로 미해결 | 61 | 호출의 반환 관측은 예외 부재 증명이 아님 |

비교 키는 바이너리, 픽스처, 네이티브 PC·명령 바이트, 경계 진입점, 경계 안의 발생 위치, **현재 분기 전까지의 PC·바이트·후속 주소**다. 주 실행 파일의 명령 바이트는 고정 ELF와 대조했다. 외부 libc의 8개 발생은 추적에 기록된 바이트이며, 주 실행 파일의 ELF 바이트로 검증하지 않는다. 서로 다른 고정 진입 상태에서 같은 선행 네이티브 경로를 지나 반대 주소로 간 경우를 관측 대응이라고 부른다. 이 조건을 만족해도 해당 상태에서 모든 입력·예외 경로를 열거했다는 뜻은 아니다. 바이트코드 문맥 등급은 **양쪽 관측 모두** 읽기 위치·수치 opcode·핸들러 진입 근거가 같을 때만 부여한다. 현재 그 조건을 만족한 발생은 6개다.

주소 `0x406879`는 Lua VM 창 안의 복사 루프에서 **한 추적에 두 번** 나온다. 첫 반복은 루프로 돌아가고 다음 반복은 빠져나온다. PC만 묶으면 양쪽 방향이 보이지만, 발생 위치와 선행 경로가 달라 같은 발생의 대체 경로로 세지 않았다. 앞에서 이탈한 Python 탐침 두 개도 목표 분기의 반대 방향 증거로 승격하지 않았다.

## 새로 증명한 Python 조건

네 실행 입력 `251, 252, 254, 255`에서 숫자 핸들러 `0x56227c`의 네이티브 분기 `0x5e978a`까지 각각 재생했다. 입력 객체의 32비트 값 필드만 `X`로 두고 타입 태그, 다른 최초 읽기 메모리, 진입 레지스터·플래그는 실행별 기록값으로 고정했다. 목표 분기 자신의 guard를 제외한 앞선 guard 40개 아래에서 `X=251`과 `X=252`가 모두 SAT였고, `251≤X≤256` 범위에서 목표 명령의 **taken 조건과 `X≥252`가 다른 경우는 UNSAT**였다. `251`은 `0x5e978c`, `252·254·255`는 `0x5e97b0`으로 진행한 실제 추적과 일치했다. 네 실행 모두 같은 추적에서 `addFive` 바이트코드 위치 6의 읽기와 핸들러 진입이 이어진다.

이 조건은 CPython 런타임의 **작은 정수 캐시 선택**에 관한 것이다. Python 원본 코드의 `if` 조건이라고 해석하지 않는다. `X=251..256` 이외의 값, 다른 객체 태그·할당기 상태, 예외 출구까지 일반화하지 않는다. 현재까지 개별 조건을 증명한 발생은 이전 Lua 2개를 포함해 **6개**이며, handler의 전체 대체 출구 집합을 닫았다고 판정한 것은 **0개**다.

## 재현

```bash
cd /workspace/R4interpreter
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_control_frontier_matrix.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_python_cache_branch_predicate.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_control_frontier_progress.py
```

마지막 스크립트는 기존 경계·Lua 분배 지도까지 포함해 작업 목록·frontier 지도·Lua/Python 조건 증명을 원본 자료에서 다시 만들고 저장본과 비교한다. 동일 PC의 다른 반복, 다른 바이트코드 픽스처, 거짓 SMT 결론, 호출의 예외 의무 삭제를 거부한다. 경계 시작점이나 Lua fetch 위치와 그 상위 hash를 함께 바꾼 경우도 원본 재계산에서 거부한다.

다음 연구 단위는 **VM 상태와 연결된 분기**를 우선 대상으로 삼는다. Lua의 나머지 다섯 입력에 같은 추적의 바이트코드 fetch를 연결하고, 분기 뒤 VM 상태 변화와 호출 인수·결과를 두 경로에서 비교한다. Python·JavaScript의 호출과 예외는 독립적으로 수집하며, 객체·메모리·수명 효과 계약이 준비된 구간만 공통 IL의 읽을 수 있는 전체 로직에 반영한다. 현재 `whole_program_complete=false`다.
