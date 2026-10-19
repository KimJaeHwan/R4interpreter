# 모르는 실행 경로에서 전이 생성과 값 IL 합성 확인

## 무엇을 확인했나

앞선 공통 숫자 IL 실험은 이미 요약한 경로에 의존했다. 이번에는 **기존 캐시 숫자 요약이 거부하는 Python 입력 `252`**의 전체 추적에서 새 구간을 골라, 기존 할당 요약을 읽지 않고 네이티브 전이를 생성했다. 그 전이를 동결한 뒤 새 입력 `255`에 적용했다. 또 선택한 구간 바로 뒤의 **다른 분배 구간**을 의미 이름 없이 생성해, 앞 경로가 다른 입력 `43`에서 재사용할 수 있는지 확인했다.

| 대상 | 새로 만든 것 | 동결 뒤 적용 |
|---|---|---|
| Python `252`의 캐시 밖 결과 경로 | 분배 후보 15개 중 결과 슬롯 포인터와 객체 type/tag/digit 쓰기를 함께 가진 유일한 구간. 146명령, P-code 읽기 47회(고유 네이티브 읽기 42개), 순서 있는 쓰기 18개, 전체 모델링한 스칼라 출력·guard·다음 주소 | 생성 직후 원본 `252` 구간에 적용 성공. 새 입력 `255`에도 읽기 42개·쓰기 18개·출력 21개 일치. 결과 객체 digit `260`, 대상 P-code 재생 0회 |
| 그 구간에 바로 이어진 미분류 분배 구간 | 기존 요약 없이 94명령의 조건부 네이티브 전이. P-code 읽기 37회(고유 27개), 쓰기 18개 | 앞 경로가 다른 Python `43`의 같은 구간에 읽기 27개·쓰기 18개 일치. 대상 P-code 재생 0회 |

첫 구간 선택에는 이전 `python_allocated_result_summary.json`, 시작·끝 PC, `146`이라는 길이, 예상 숫자 `257`을 사용하지 않았다. **선택 목표는 Python 객체 결과의 구조**였다. 출력 슬롯은 구간 끝의 `R15-8`로 잡고, 그 슬롯에 쓰인 포인터가 가리키는 객체의 `+8/+16/+24` 필드 쓰기가 같은 후보 안에 있는지 확인했다. 후보가 둘 이상이면 생성을 중단한다. 생성 뒤에만 이전 할당 요약을 읽어 경로 hash와 guard·상태·읽기·순서 있는 쓰기·후속 주소가 모두 일치함을 회귀 비교했다.

## 값 증명과 두 경로의 IL

첫 구간의 **최종 계산 메모리**에서 결과 슬롯 포인터를 읽고, 그 포인터의 type/tag/digit을 decode했다. 입력 객체의 digit을 기호 `X`로 바꾼 뒤 한 관측 모델에서 `X+C` 후보를 얻었다. `C=5`였고 고정된 나머지 진입 상태·첫 읽기 메모리·FS/GS·allocator 환경에서 `252≤X≤256`의 guard 이탈, 결과 digit과 `X+5`의 불일치, type/tag 불일치, 결과 포인터가 입력 객체 또는 출력 슬롯의 **시작 주소와 같은** 반례, 결과 포인터가 정적 숫자 캐시 범위에 있는 반례가 모두 `unsat`였다. `X+6`의 불일치 반례는 `sat`이다. 객체 범위 전체의 비중첩이나 논리적 `Allocate`·freshness는 증명하지 않았다.

기존 캐시 경로 `5..251`과 새 할당 경로 `252..256`은 숫자값에 대해서는 같은 **3노드 `BV32 X+5` IL**을 공유한다. 캐시 경로는 12개의 순서 있는 쓰기, 할당 경로는 18개의 순서 있는 쓰기와 서로 다른 결과 decode 계약을 유지한다. 이는 두 **대체 경로의 조건부 값 합성**이다. 모든 VM 상태에서 둘 중 하나로 진입한다는 경로 완전성이나 두 네이티브 전이를 순서대로 실행하는 합성을 증명한 것은 아니다.

## 거부 사례와 한계

[결과 JSON](unseen_python_family_result.json)의 22개 부정 입력에는 잘못된 읽기 주소·값, FS base와 종료 GS base, 이전에 쓴 바이트를 읽을 때의 잘못된 값, 누락·순서 변경된 쓰기, 변조된 결과 포인터·type/tag/digit·후속 주소, 분배 edge와 중간 명령의 제거·순서 변경이 있다. 전이 적용기에 정상 진입 상태와 메모리를 유지한 채 저장된 효과 또는 후속 주소만 바꾼 **코어 자체의 부정 검증**도 포함한다. 캐시 경로와 할당 경로의 교차 적용 및 범위 밖 `257` 메타데이터도 거부했다. `257`은 실제 네이티브 실행을 수집한 결과가 아니라 계약의 범위 검사다.

적용기는 FS/GS base를 입력으로 쓰는 구간에서 각 x86 명령이 허용된 scalar 명령인지, 명시적 세그먼트 레지스터 쓰기가 없는지, 모든 추적 행의 진입·종료 base가 고정값인지 확인한다. 또한 각 메모리 접근을 순서대로 읽고 써서 반복 읽기와 쓰기 후 읽기의 바이트값 일관성을 확인한다. 원본 `252` 구간에서 쓰기 후 읽기 바이트 65개, 새 `255`와 다른 선행 경로의 이웃 구간에서 각각 65개와 56개를 확인했다. [이웃 결과](unseen_python_neighbor_result.json)에는 종료 FS base 및 쓰기 후 읽기값 변조 거부도 있다.

94명령 이웃 구간은 **네이티브 전이 생성·재사용**까지만 성공했다. 이 구간의 바이트코드 이름, 호출/반환 의미, VM 상태의 논리적 출력은 자동 판정하지 못했다. 첫 146명령 구간도 Python 객체 필드 위치와 허용 숫자 영역을 사람이 제공했다. 따라서 이번 결과는 “모르는 handler의 높은 수준 의미를 완전 자동 복원”한 사례가 아니다. 전체 코드를 읽으려면 VM 상태의 입력·출력 의미를 찾는 과정, 분기/예외 경로 열거, allocator·alias 조건, 여러 구간의 효과 보존 합성이 더 필요하다.

기계 판독 자료: [생성한 146명령 전이](unseen_python_generated_transition.json), [후보·값 증명](unseen_python_generated_proof.json), [두 숫자 경로 적용](unseen_python_family_result.json), [이웃 94명령 전이](unseen_python_neighbor_transition.json), [이웃 적용](unseen_python_neighbor_result.json).

## 재현

```bash
cd experiments/interpreter-expression
../vm-transition-testbed/.venv/bin/python probe_unseen_python_path.py freeze
../vm-transition-testbed/.venv/bin/python probe_unseen_python_path.py apply
../vm-transition-testbed/.venv/bin/python probe_unseen_python_path.py freeze_neighbor
../vm-transition-testbed/.venv/bin/python probe_unseen_python_path.py apply_neighbor
```

새 입력 `255` 추적은 `trace_python_holdout.py 255 artifacts/next_unseen_python_255.json.gz`로 수집했다. 동결 단계는 저장된 `252` 전체 추적과 고정 CPython 바이너리를 읽고, 적용 단계는 `255` 추적을 읽는다. 모든 산출물은 `R4interpreter`에만 저장했다.
