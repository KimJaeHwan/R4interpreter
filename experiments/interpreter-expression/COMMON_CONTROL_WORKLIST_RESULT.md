# 세 엔진 공통 제어 흐름 작업 목록

## 목적과 범위

기존 [공통 프로그램 표현](COMMON_PROGRAM_REPRESENTATION_RESULT.md)의 관측 구간마다 네이티브 조건 분기와 호출을 하나씩 작업 목록에 올렸다. 항목의 단위는 주소가 아니라 **해당 실행 기록의 해당 명령 순서**다. Lua에서 같은 PC `0x406879`가 같은 실행 중 159번째와 166번째에 나타나도 별개 항목이다. 이 표현은 바이트코드 복원 없이 아직 확인해야 할 제어 경로를 공통 형식으로 관리하기 위한 것이다.

`common_control_worklist_v1.json`에는 Python 전체 관측 경로 4개, Lua 로컬 핸들러 구간 1개, JavaScript 로컬 구간 1개, Lua 입력→출력 연속 VM 구간 7개가 있다. 각 항목은 엔진·바이너리·픽스처 해시, 입력 바인딩, 소스 추적 해시, 실행 순서, PC, 관측 후속 주소와 탐색할 반대쪽 주소를 보존한다. Lua 연속 VM 구간에는 원시 추적의 시작 명령 번호도 기록해 구간 내부 순서를 원시 번호로 환산할 수 있다. P-code guard 순서가 연결된 경우에는 그 순서와 증명의 적용 범위도 보존한다. 호출에서는 관측 대상과 정상 복귀를 기록하되 예외 경로는 미해결로 둔다.

| 엔진 | 구간 수 | 조건 분기 발생 | 호출 발생 | 다른 추적에서 반대쪽 관측 | 소스 고정 조건의 반대쪽 UNSAT |
| --- | ---: | ---: | ---: | ---: | ---: |
| Python | 4 | 489 | 48 | 3 | 92 |
| Lua | 8 | 166 | 13 | 21 | 0 |
| JavaScript | 1 | 4 | 0 | 0 | 0 |

마지막 두 열은 서로 다른 의미다. 다른 추적에서 반대쪽이 보였다는 사실은 그 추적의 사실일 뿐, 원래 입력과 환경에서도 도달 가능하다는 증명은 아니다. UNSAT 역시 기록된 입력 범위·고정 진입 환경·이전 guard 아래에서의 결과이며 전역 불가능성 증명이 아니다. Lua 7개 값 체인의 제어 목록은 연속 VM 구간 내부에 한정된다. 값 감시가 끊긴 구간이나 JavaScript 호출자 전체 경로는 포함하지 않는다.

## Python 후보의 실제 실행 판정

소스 입력 `252`의 P-code SMT 질의는 현재 분기 조건을 제외한 이전 경로 조건만 고정한다. 후보가 SAT여도 실제 프로세스에서 이전 분기가 먼저 바뀔 수 있으므로 실행 기록으로 다시 분류했다.

| 후보 주소 / 원래 발생 | 대상 입력 | 결과 | 첫 관련 명령 / 다음 작업 |
| --- | ---: | --- | --- |
| `0x5a82b0` / `python_252:branch:158` | `0` | `earlier_divergence` | 133번째 `0x5a8250`; `python_252:branch:133` |
| `0x5e978a` / `python_252:branch:764` | `251` | `target_opposite_observed` | 764번째의 반대쪽을 관측. 소스의 고정 진입 환경 재현 증명은 없음 |
| `0x5a82b0` / `python_252:branch:158` | **새 입력 `1`** | `target_same_edge` | 158번째에 도달했지만 원래 후속 주소를 선택 |
| `0x5e978a` / `python_252:branch:764` | **새 입력 `1`** | `earlier_divergence` | 331번째 `0x5309a8`; `python_252:branch:331` |

새 입력 `1`은 SMT 모델로 생성한 증인이 아니라 독립적인 실제 실행 관측이다. 따라서 질의 상태는 `not_queried`로, 대상의 원래 P-code guard 번호는 별도 필드로 기록했다. 원시 기록은 [추적](artifacts/python_control_probe_x1.json.gz)과 [마커](artifacts/python_control_probe_x1.marker.json)에 있다. 동일 Python 픽스처 바이트코드와 고정 바이너리를 사용해 함수 반환까지 1002개 네이티브 명령을 추적했고 하드웨어 메모리 감시가 켜져 있었다. 반환값은 `1+5=6`이다. 이 사실은 새 경로의 전체 상태 요약을 동결하거나 재사용했다는 뜻은 아니다.

검사기는 잘린 기록을 `target_not_reached`, 불가능한 후속 PC를 `trace_invalid`로 분류한다. 저장된 증거의 명령 순서·주소·픽스처·입력 환경·추적을 바꿔 보는 11개 부정 대조도 거부했다. 특히 정상 복귀를 호출의 예외 경로 부재로 바꾸는 경우, 앞선 이탈을 후보 적중으로 바꾸는 경우, Lua 반복 PC의 다른 발생을 끼워 넣는 경우를 거부한다. 이 11개는 저장된 증거의 무결성 검사이며 SMT 구현에 오류를 주입해 검증한 결과는 아니다.

## 재현

저장된 IL을 원천 자료에서 다시 만들고, Python의 기존 SMT 후보 및 세 입력의 실제 기록을 다시 판정한다.

```bash
cd /workspace/R4interpreter
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_common_control_worklist.py
```

새 입력의 원시 기록을 다시 수집하려면 동일 바이너리와 같은 픽스처 환경에서 다음 명령을 사용한다. 실행마다 주소 배치가 달라질 수 있으므로 새 기록을 기존 해시와 그대로 비교하는 명령은 아니다.

```bash
cd /workspace/R4interpreter
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_cross_full_flow.py --watch-bridge --through-return python /usr/bin/python3.13 /tmp/r4_branch_x1.marker.json /tmp/r4_branch_x1.json.gz -I -S /workspace/R4interpreter/experiments/interpreter-expression/python_branch_fixture.py 1 --mark /tmp/r4_branch_x1.marker.json --native-sync
```

## 다음 작업

첫 이탈 분기를 새 후보로 따라가되 입력만으로 해결할 수 있는 조건과 호출자·힙·예외 상태에 의존하는 조건을 분리해야 한다. 그 뒤 각 분기의 후보 후속 경로를 실제로 추적하거나 SMT로 제한된 불가능성을 증명하고, 호출의 정상·예외 후속 경로를 독립적으로 기록해야 한다. JavaScript 호출자와 Lua 값 감시 간격은 전체 상태 연결 증거가 생긴 뒤 작업 목록에 추가한다. 목록이 늘어나는 것만으로 전체 스크립트 로직이 복원되지는 않는다.
