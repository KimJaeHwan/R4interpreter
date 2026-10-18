# Python 할당·JavaScript 문자열 경로와 값 축약

## 이번 실험에서 확인한 것

기존 공통 전이 형식에 두 사례를 추가했다. CPython의 `252 + 5` 결과가 캐시 밖에 새 PyLong으로 할당되는 경로와, V8 Ignition의 두 자리 문자열 `"37" + 5`가 `"375"`가 되는 경로다. 같은 실행 파일의 다른 입력에 저장된 P-code 식을 적용했다. 대상 실행의 P-code를 다시 재생하지 않았다.

| 소스 경로 | 전체 경로 요약 | 다른 실행에서 적용 | 사람이 읽을 값 투영 |
|---|---|---|---|
| Python 입력 252 | 네이티브 146개, P-code 726개, 읽기 42개, 순서 있는 쓰기 18개, guard 26개 | 253·254·256의 새 PyLong 경로 3/3 일치 | 결과 객체의 4바이트 digit = `X + 5` (`X`는 252~256) |
| JavaScript 문자열 `"37"` | 네이티브 230개, P-code 1055개, 읽기 48개, 순서 있는 쓰기 30개, guard 55개 | `"38"` 경로 1/1 일치 | 출력 객체의 연속 3바이트 = 입력 두 ASCII 숫자 + `'5'` |

각 요약에는 16개 범용 레지스터, 모델링한 플래그 5개, 읽기 목록, 쓰기의 순서·주소·폭·값, 다음 처리 경계를 저장했다. Python은 대상 프로세스마다 달라지는 `FS_BASE`를 진입 입력으로 바인딩했다. 할당된 PyLong의 refcount·type·size tag·digit, 결과 슬롯 포인터도 확인한다. JavaScript는 문자열 객체의 길이와 두 문자, `AddSmi`의 실제 즉값 5를 진입 계약에서 확인한다. 새 경로는 각각 [Python 요약](python_allocated_result_summary.json)과 [JavaScript 요약](js_string_add_full_handler_summary.json)에 있다.

[공통 적용 결과](common_three_engine_application_result.json)는 이전 Lua·Python·JavaScript 사례까지 **대상 14건 중 12건 일치, 2건 `unknown`**이다. 거부한 두 사례는 기존 JavaScript 숫자 252와 이번에 추가한 세 자리 문자열 `"251"`이다. 의도적으로 바꾼 즉값, PyLong digit, `FS_BASE`를 포함한 부정 입력 13개도 모두 `unknown`으로 거부했다. 해당 대상은 저장된 식 평가와 관측 상태·효과의 차등 대조로 확인했으며, 대상 P-code 재생 횟수는 0이다. 이는 실제 네이티브 추적에서 읽기·쓰기와 경로를 확보한 뒤의 적용 결과다.

## 네이티브 요약에서 값 식으로 축약

[값 투영 결과](expanded_value_projection_result.json)는 전체 전이 요약과 별도로, 결과값에 도달하는 짧은 P-code 구간을 선택해 SMT로 검사한다. Python에서는 피연산자 digit이 레지스터에 적재된 뒤의 연산 구간이 `X+5`를 만들고, 할당을 지나는 구간이 그 값을 `RCX`에 유지하며, 마지막 객체 digit 쓰기가 그 값을 저장한다. `X ∈ [252,256]`에서 각 구간의 경로 조건이 성립하고 다른 값이 나올 수 없다는 반례 질의가 모두 `unsat`였다. 관측된 252·253·254·256에서도 객체 digit과 스크립트 출력이 일치했다.

JavaScript에서는 원본 문자열에서 한 바이트씩 읽어 결과 객체에 쓰는 두 짧은 구간과 `'5'`를 쓰는 구간을 별도로 검사했다. 입력 문자가 ASCII 숫자일 때 각 복사값이 원본 문자와 다르거나, 끝 문자가 `'5'`가 아닌 반례 질의가 `unsat`였다. 소스 `"37"`과 대상 `"38"`에서 반환 문자열 객체의 문자 저장 위치가 연속이며 실제 출력 `"375"`·`"385"`와 일치했다.

실제 출력 대조는 결과 주소에 대한 **모든 네이티브 쓰기를 순서대로 합쳐 최종 바이트를 재구성**한다. 나중의 겹치는 쓰기를 놓친 채 특정 폭의 쓰기 하나만 고르지 않는다. 입력 추적과 바이너리의 SHA-256도 결과에 기록한다.

이것은 **결과값만 보는 투영**이다. Python의 18개 쓰기를 4바이트 digit 하나로, JavaScript의 30개 쓰기를 문자 3개로 바꾸어 실행 가능한 전체 전이라고 주장하지 않는다. 할당, 참조계수, 스택, 객체 메타데이터, 후속 실행에 필요한 레지스터와 메모리 효과는 원래의 전체 네이티브 요약에 남겨 둔다. 값 증명은 내부 관측 cutpoint의 다른 레지스터·메모리를 소스 실행 값으로 고정하므로, 임의 초기 상태와 임의 alias에서 모든 경로가 이 식에 도달한다는 증명이 아니다. 선택된 값 의존성을 `daasdmlkas`에 수정해 넣은 것은 아니며, 그 저장소는 그대로 두었다.

## 경로가 아직 열린 곳

- 세 자리 문자열 `"251"`은 232개 명령의 다른 네이티브 경로로 `"2515"`를 만든다. 두 자리 문자열 요약은 이 경로를 거부한다. 이 경로를 하나의 일반 문자열 반복식으로 합치는 증명은 남아 있다.
- `37n + 5`는 JavaScript에서 `TypeError`를 낸다. 243개 명령을 추적했으나 기록은 내부 런타임 간접 분기 명령 `0xe36e62`에서 목적지 `0xe3730d`로 이동하는 시점에 끝나며 `Throw` 또는 catch 경계까지 이어지지 않았다. 현재 P-code 재생 모델은 이 경로의 XMM 상위 레지스터 접근도 처리하지 못한다. 오류 전이는 아직 `unknown`이다.
- P-code에서 결과 바이트의 역방향 의존성을 더 일반적으로 찾고, 호출자 기준 생존성·메모리 alias·할당 객체 정체성을 증명해야 전체 네이티브 효과를 안전하게 지운 축약 전이가 된다. 경계·입력 계약의 자동 발견과 다른 프로그램·런타임 버전으로의 이식도 아직 확인하지 않았다.

## 재현

고정 바이너리와 저장된 추적이 있는 이 저장소 루트에서 실행한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_expanded_native_paths.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/common_observed_transition.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/project_expanded_values.py
```
