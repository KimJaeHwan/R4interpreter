# 공통 구간 적용기: JavaScript 루프와 Lua 명령 분배

## 목적과 결과

[JavaScript 문자열 루프 실험](JS_STRING_LOOP_COMPOSITION_RESULT.md)에서 사용한 구간 평가를 문자열 처리 전용 코드에서 분리했다. [공통 구간 적용기](composed_native_transition.py)는 x86-64 P-code에서 저장한 SMT 식을 읽어 **경로 guard, 읽기 주소·값, 순서 있는 쓰기, 16개 범용 레지스터, 플래그 5개, 후속 주소**를 계산하고 네이티브 추적과 대조한다. 언어별 opcode 뜻이나 문자열·Lua 숫자 규칙은 이 코드에 없다.

같은 적용기를 두 종류의 합성에 사용했다.

| 대상 | 구간 구성 | 결과 |
|---|---|---|
| JavaScript 문자열 `+ 5` | 앞 구간 → 두 문자 복사 반복 → 홀짝 뒤 구간 | 2~11자리 10건 전체 전이 일치, 12~16자리 5건 `unknown` |
| Lua 정수 `x + 7; + 11` | 숫자 핸들러 → fetch/decode/dispatch → 숫자 핸들러 | 6개 입력에서 각각 51개 네이티브 명령의 전체 전이 일치 |

Lua의 여섯 입력은 분배 구간을 동결할 때 사용한 `9`와 별도 적용 입력 `0`, `1`, `-1`, `INT64_MAX`, `INT64_MIN`이다. 첫 처리 결과는 각각 `16`, `7`, `8`, `6`, `-9223372036854775802`, `-9223372036854775801`; 두 번째 결과는 `27`, `18`, `19`, `17`, `-9223372036854775791`, `-9223372036854775790`이었다. 두 번째 핸들러의 진입 레지스터·플래그·메모리는 첫 핸들러와 분배 구간의 **계산된 출력**으로 구성했고, 대상 추적의 두 번째 진입 상태는 검증에만 사용했다.

## Lua 구간을 만든 방법

기존 [숫자 핸들러 요약](handler_summary_plus7.json)은 23개 네이티브 명령의 P-code 265개에서 만든 식·효과를 그대로 가져왔다. 그 뒤의 5개 명령에서 바이트코드 읽기, opcode 인덱스 추출, 읽기 전용 점프 테이블 참조, 간접 분배를 P-code 21개로 모델링해 [분배 구간](lua_handler_bridge_composed_summary.json)에 저장했다. 이 구간의 읽기 2개와 쓰기 0개, 전체 출력 상태, 실제 후속 주소를 소스 추적과 대조한 후 요약을 동결했다. 두 번째 핸들러에는 첫 번째와 같은 요약을 적용한다.

Lua 어댑터는 고정 ELF·바이트코드 이미지의 해시, 실제 첫 명령 워드, 다음 명령 워드의 파일 위치, ELF 읽기 전용 분배 테이블을 확인한다. 앞 핸들러가 코드나 분배 테이블을 덮으면 `unknown`으로 거부한다. 이 바인딩과 구간 경계 선택은 Lua 대상에 필요한 작업이고, guard·읽기·쓰기·상태·후속 주소 평가는 두 엔진이 같은 코드를 쓴다.

[Lua 적용 결과](lua_handler_bridge_application_result.json)는 **6건 일치, 불일치 0건**이다. 변조된 네이티브 쓰기, 분배 경로, 두 번째 진입 snapshot 3건은 `unknown`으로 거부했다. 두 번째 진입 snapshot은 계산 입력으로 쓰지 않고 일치 여부만 확인한다. 적용 중 소스·대상 P-code 재생은 모두 0회다. [JavaScript 적용 결과](js_string_frozen_loop_application_result.json)도 공통 적용기로 다시 생성했으며 기존 10건 일치·5건 `unknown` 결과를 유지했다.

## 공통화 범위

이번 실험은 문자열 복사와 Lua 숫자·분배처럼 다른 동작에도 **동일한 구간 전이 평가와 메모리 효과 합성**을 사용할 수 있음을 보여준다. 두 대상의 최상위 JSON은 각각 루프와 고정 순서를 나타내며, 반복 횟수 선택·바이트코드 바인딩·경계 발견은 아직 어댑터 코드에 있다. 따라서 모든 타입을 자동 분석하거나 전체 Lua 프로그램의 시작부터 반환까지 한 요약으로 표현한 결과는 아니다.

두 적용 모두 대상 네이티브 추적에서 실제 경로와 최초 읽기 메모리를 받는다. Lua는 첫 핸들러의 진입 상태도 추적에서 받는다. 고정 경로 밖의 타입 변환·할당·예외·다른 dispatch 경로는 `unknown`이다. 다음 공통화 시험에는 Python 객체 할당이나 예외처럼 새 효과 종류가 필요한 사례를 붙여, 현재의 `Write` 중심 효과 형식이 어디서 부족한지 확인해야 한다.

## 재현

저장소 루트에서 저장된 추적과 실험용 Python 환경을 사용한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/freeze_lua_handler_bridge_segments.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_lua_handler_bridge_summary.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_js_string_loop_summary.py
```
