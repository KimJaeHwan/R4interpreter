# 전체 로직 복원: 분기 조건과 바이트코드 커서 연결

이 단계는 [기존 경계 지도](boundary_relevance_map_v1.json)의 선택된 발생에 [추가 증거](boundary_evidence_extension_v1.json)를 연결한다. 이전 지도를 덮어쓰지 않는다. 기존 지도에서 미증명으로 표시된 첫 Lua 분기 조건을 독립적으로 증명했고, Python·JavaScript의 선택된 숫자 구간 앞에서 실제 바이트코드 읽기와 네이티브 핸들러 진입을 같은 실행 기록으로 확인했다.

## Lua: 한 명령의 분기 조건

입력 `0`과 `9`의 고정된 원시 추적을 각각 `0x415f30`까지 P-code로 재생했다. 실행 입력 `X`는 하드웨어 쓰기 감시와 기존 입력 연결 증명으로 VM 소스 슬롯에 묶었다. 그 밖의 최초 읽기 메모리, 진입 레지스터와 플래그는 해당 실행 기록의 값으로 고정했다.

각 추적에서 **목표 분기 자신의 guard를 제외한** 앞선 guard 12개를 놓고 SMT를 물었다. 그 조건 아래 `X=0`과 `X≠0`이 모두 가능했고, 목표 명령의 원시 taken 조건과 `X==0`이 다르게 되는 경우는 불가능했다. 입력 `0`에서는 taken 후속 주소 `0x415d51`, 입력 `9`에서는 fallthrough `0x415f36`을 관측했다. 목표 guard를 앞선 조건에 몰래 포함하면 양쪽 입력 가능성 검사에서 탈락한다. 입력 슬롯의 관측값이나 분기 후속 주소를 바꾼 대조 사례도 거부했다.

따라서 [Lua 조건 증명](lua_native_branch_predicate_v1.json)은 **이 두 고정된 진입 상태와 선행 경로 아래**에서 `0x415f30`의 조건이 `X==0`임을 말한다. 모든 Lua VM 상태나 실행되지 않은 경로에 대한 증명은 아니다.

## Python·JavaScript: 같은 추적의 읽기 → 분배 → 진입

| 엔진·입력 | 바이트코드 읽기와 커서 | 분배·핸들러 진입 | 현재 위치 증거 |
| --- | --- | --- | --- |
| Python `252`의 `addFive` | 첫 자식 함수 읽기 `0x95`; 선택된 읽기 `0x2d`, 주소 차이 6바이트 | `0x2d`를 인덱스로 읽은 점프 테이블 값 `0x56227c`와 숫자 구간 진입 주소가 일치 | 고정 CPython 3.13으로 픽스처의 코드를 재생성한 명령 목록에서 위치 **6**과 일치 |
| JavaScript `43`의 자식 함수 | 첫 자식 함수 읽기 `0x0b`; 선택된 읽기 `0x4b`, 주소 차이 2바이트 | `0x4b`의 점프 테이블 값 `0x1bb7780`와 숫자 구간 진입 주소가 일치 | 같은 추적의 자식 함수 첫 읽기 기준 **상대 위치 2**; 배열 시작 절대 위치는 미확인 |

[커서 증거](cross_same_trace_cursor_v1.json)는 두 경우 모두 네이티브 메모리 읽기 주소와 값, 분배 레지스터, 테이블 주소·값, 다음 PC를 확인한다. Python에서는 같은 실행의 코드 객체 포인터와 첫 커서를 연결하고, **고정 픽스처에서 별도 재생성한** 명령 목록의 전체 내용·코드 해시·길이를 대조해 위치 0을 정했다. `code object + 0xc8`의 첫 바이트 주소는 이 CPython 빌드에서 관측한 배치 조건이다. JavaScript `43`은 기존 로컬 `holdout-37` 구간과 다른 전체 추적이다. 두 구간을 같은 바이트코드 파일이라고 합치지 않는다. 잘못된 읽기 바이트·커서·테이블 목표 여섯 사례는 거부했다. 이 검사는 **관측 실행의 값과 주소 연결**이며, 모든 입력에서 커서 식이 성립한다는 증명은 아니다.

이 결과가 보여 주는 공통 절차는 `VM 입력값 → 관측한 byte fetch → 커서 변화 → 테이블 선택 → 네이티브 핸들러 진입 → 상태 변화`다. 각 엔진의 바이트코드 포맷과 절대 위치 기준은 별도 어댑터가 필요하다. Python의 `6`과 JavaScript의 상대 `2`는 서로 같은 opcode나 같은 의미라는 뜻이 아니다.

## 재현과 남은 단계

```bash
cd /workspace/R4interpreter
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_lua_native_branch_predicate.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/map_cross_same_trace_cursor.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_boundary_evidence_extension.py
```

마지막 스크립트는 기존 경계 지도와 두 새 증거를 원본 자료에서 재구축해 저장본과 비교한다. 상위 지도 분기 주소, Lua 증명 결론, Python 커서 위치, JavaScript 추적 해시를 바꾼 네 경우를 거부한다.

이제 첫 Lua 대체 분기의 **개별 조건식과 두 관측 후속 주소** 및 선택된 Python·JavaScript 숫자 진입의 바이트코드 연결을 확인했다. 다음에는 이 방식으로 **다른 분기 양쪽 경로와 호출·예외 출구**를 수집하고, VM 상태의 객체·메모리·수명 효과를 안전하게 요약해야 한다. 그 증거를 구간별 공통 IL과 합쳐 읽을 수 있는 전체 로직으로 출력하는 단계도 남았다. 현재 `whole_program_complete=false`다.
