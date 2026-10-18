# Python PyLong 할당 경로와 공통 전이 효과

## 실험 질문

문자열 복사와 Lua 숫자·분배에 적용한 [공통 네이티브 구간 코어](CROSS_ENGINE_SEGMENT_COMPOSITION_RESULT.md)가 Python의 **새 객체를 만드는 경로**에도 적용되는가? 그리고 바이트 단위 `Write` 효과만으로 객체의 논리적 할당까지 표현할 수 있는가?

고정 CPython 3.13.5 실행기의 `x + 5`를 사용했다. `x=252`에서는 결과 `257`이 작은 정수 캐시를 벗어나 한 자리 PyLong 객체를 만드는 146개 네이티브 명령 경로를 지난다. 기존 [할당 경로 요약](python_allocated_result_summary.json)의 P-code 연산 726개에서 읽기 값 식까지 포함한 [공통 구간 JSON](python_allocated_composed_summary.json)을 동결했다. 새 요약의 guard, 출력 상태, 쓰기, 후속 주소, 읽기 주소 식은 기존 요약과 동일한지 비교했다.

## 적용 결과

| 입력 `x` | 결과 | 처리 |
|---:|---:|---|
| 252, 253, 254, 256 | 257, 258, 259, 261 | 각 146개 명령의 상태·읽기 42개·순서 있는 쓰기 18개 일치 |
| 251 | 256 | `unknown`; 캐시 정수 포인터를 재사용하는 116개 명령의 다른 경로 |

252는 소스 경로이며 253·254·256은 별도 적용 입력이다. 적용 중 소스·대상 P-code 재생은 0회다. 결과 포인터는 네 실행에서 서로 다른 힙 주소였지만, 같은 구간 식이 포인터·객체 필드·결과 슬롯 쓰기를 각각 계산했다. 계산된 쓰기를 순서대로 합치면 각 객체의 참조계수 `1`, 타입 포인터, 크기 태그 `8`, 4바이트 digit `x+5`와 결과 슬롯의 객체 포인터가 관측 결과와 일치한다. `FS_BASE`·`GS_BASE`는 Python 어댑터가 진입 상태에서 제공한다. [적용 결과 JSON](python_allocated_composed_application_result.json)에 주소와 필드별 근거가 있다.

캐시 경로 `x=251`은 결과 포인터가 정적 작은 정수 캐시 내부에 있고, 할당 경로 요약의 입력 조건에 맞지 않아 `unknown`이다. 의도적으로 바꾼 객체 digit 쓰기와 `FS_BASE`의 두 부정 입력도 거부됐다. 이전 [Python 할당 실험](EXPANDED_PATH_VALUE_PROJECTION_RESULT.md)의 3개 별도 입력 결과를 **같은 JavaScript·Lua 공통 구간 적용기**에서도 재현한 것이 이번 실험의 새 확인 사항이다.

## `Write`와 `Allocate`의 차이

**현재 `Write` 효과는 이 관측 경로의 네이티브 메모리 변화를 재현하기에 충분했다.** 하지만 `Write(ptr, bytes)`만으로는 `ptr`에 새로운 *논리적 객체 수명*이 시작했다는 사실, 다른 살아 있는 객체와 별칭이 없다는 사실, 이후 안전하게 재사용할 수 있는 영역이라는 사실을 표현하지 못한다.

실제 네 추적 모두 새 객체의 첫 필드를 쓰기 전에 그 주소의 기존 8바이트 값을 읽었다. 따라서 주소의 바이트가 이전부터 존재했다는 것이 관측되며, 단순히 “처음 등장한 주소이므로 새 메모리”라고 판정할 수 없다. 네 번의 포인터가 서로 다르다는 사실도 각 프로세스의 전체 힙에 대한 freshness 증명은 아니다. 결과 JSON의 `allocation_event_proved`를 모두 `false`로 남겼다.

공통 요약에서 객체 수명을 안전하게 다루려면 `Allocate`를 `Write`와 별도 효과로 넣고, 크기·정렬·객체 정체성·기존 live 객체와의 비별칭·할당 실패/예외 경로를 근거와 함께 모델링해야 한다. 그 근거가 없으면 현 단계에서는 **관측된 네이티브 쓰기 전이**까지만 주장하고 논리적 할당은 `unknown`으로 둔다. 입력 경로와 최초 읽기 메모리는 대상 네이티브 추적에서 받으므로, 임의 힙 상태에 대한 정적 할당 증명은 아니다.

## 재현

저장소 루트에서 저장된 추적과 실험용 Python 환경으로 실행한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/freeze_python_allocated_segment.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_python_allocated_segment.py
```
