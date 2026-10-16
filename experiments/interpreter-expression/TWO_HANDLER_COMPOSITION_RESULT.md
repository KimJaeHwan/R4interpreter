# Lua 덧셈 두 번의 상태 전이 합성

상태: [확장 관문](VM_HANDLER_SUMMARY_DESIGN.md) 통과. 기존 [단일 처리 구간 요약](TRANSITION_SUMMARY_RESULT.md)을 수정하지 않고 명령 위치·슬롯이 다른 바이트코드에 재사용한 뒤, 첫 처리 구간의 출력과 fetch/decode/dispatch를 연결해 두 번째 처리 구간의 입력을 계산했다. 코드와 원시 증거는 R4interpreter에만 저장했다.

## 새 바이트코드와 처리 구간

[평가용 Lua 소스](lua_chunk_two_adds_source.lua)는 `local first = x + 7; return first + 11`이다. 소스는 평가용 바이트코드를 만드는 데만 사용했다. [디버그 정보 없는 바이트코드](lua_chunk_two_adds.luac)의 32비트 명령 워드는 파일 오프셋 `47`에서 `0x86000015`, 오프셋 `55`에서 `0x8a000095`이다. [원시 VM 명령 추적](artifacts/lua_trace_two_adds_x9.csv)과 [바이트코드 위치·분배 대응](bytecode_handler_map_two_adds_x9.json)에서 실행된 인덱스 `2`, `4`의 하위 7비트 분배 값이 모두 `21`이고 네이티브 진입이 `0x4164b8`임을 확인했다. 두 번째 워드는 첫 실험의 `x+11` 워드 `0x8a000015`와 달라 대상 VM 슬롯이 이동한다.

동결된 [handler_summary_plus7.json](handler_summary_plus7.json)을 바꾸지 않고 두 진입에 각각 적용했을 때, 입력 `9`의 첫 payload는 `16`, 둘째 payload는 `27`이었다. 쓰기 주소는 첫 결과 슬롯에서 다음 슬롯으로 **16바이트** 이동했고, 두 경우 모두 tag는 `3`이었다. [검증 코드](validate_lua_composition.py)는 이 독립 적용을 모든 입력에서 별도로 확인한다.

## 두 번째 진입을 계산한 방법

첫 handler 요약은 다음 fetch 직전 `0x415b24`에서 끝난다. 이어 실행된 네이티브 명령 `0x415b24`, `0x415b27`, `0x415b2b`, `0x415b2e`, `0x415b31`의 Low P-code **21개**를 빠짐없이 재생했다. 여기에는 다음 명령 워드의 4바이트 읽기, 하위 7비트 추출, ELF 읽기 전용 점프 테이블의 8바이트 읽기, 간접 분기가 들어 있다. [연결 전이 요약](lua_handler_dispatch_bridge.json)은 [생성 코드](build_lua_dispatch_bridge.py)가 바이트코드 위치 대응을 근거로 만들었다.

연결 전이의 시작 레지스터와 메모리는 **첫 handler 요약의 출력식 및 두 순서 있는 쓰기**로 구성했다. 다음 워드의 바이트는 `.luac`의 위치 대응에서, 점프 테이블 값은 같은 해시의 ELF 읽기 전용 구간에서 가져왔다. 이를 통해 두 번째 `W=0x8a000095`, 분배 목표 `0x4164b8`, 두 번째 진입 레지스터와 VM 메모리를 계산했다. [합성 코드](compose_lua_two_adds.py)는 이 예측 상태를 두 번째 handler 요약에 넣는다. 두 번째 진입의 실행 snapshot은 **예측 입력으로 사용하지 않고**, 계산이 끝난 뒤 레지스터·선택 플래그·256바이트 VM 메모리를 대조하는 데만 썼다.

| 실행기 입력 | 첫 payload | 둘째 payload의 부호 있는 값 | 실행기 출력 |
|---:|---:|---:|---:|
| `9` | `16` | `27` | `27` |
| `0` | `7` | `18` | `18` |
| `1` | `8` | `19` | `19` |
| `-1` | `6` | `17` | `17` |
| `INT64_MAX` | `9223372036854775814` | `-9223372036854775791` | `-9223372036854775791` |
| `INT64_MIN` | `9223372036854775815` | `-9223372036854775790` | `-9223372036854775790` |

입력 `9` 추적으로 연결 전이를 생성했고, 나머지 **5개는 별도 검증**이다. 6개 모두 두 번째 진입 상태, 쓰기 효과, 최종 출력이 일치했다. 두 번째 워드의 분배 값만 시험용 파일 사본에서 바꾸면 다른 점프 테이블 항목으로 향해 요약은 `unknown(outside conditional path)`을 반환했다. 이 시험은 수정된 바이트코드를 실제로 실행한 결과는 아니다. 입력별 예측 주소, 원시 추적 및 요약 해시는 [검증 결과](lua_composition_validation.json)에 있다.

## 재현

기존 실험 Python 환경에서 `experiments/interpreter-expression`을 현재 작업 디렉터리로 두고 실행한다.

```bash
python build_lua_dispatch_bridge.py handler_summary_plus7.json artifacts/lua_bundle.tar.gz artifacts/lua_two_adds_x9.jsonl lua_interpreter_fixture lua_handler_dispatch_bridge.json --bytecode-map bytecode_handler_map_two_adds_x9.json
python validate_lua_composition.py
```

원시 추적을 다시 수집할 때는 다음처럼 두 처리 구간과 그 사이 명령을 함께 기록한다.

```bash
python trace_input_provenance.py ./lua_interpreter_fixture ./lua_chunk_two_adds.luac 9 artifacts/lua_two_adds_x9.jsonl --limit 100000 --capture-handler --handler-count 2 --markers-only
```

바이트코드 위치 대응은 [명령 단위 추적기](ptrace_instruction_trace.c)를 빌드한 뒤 다음처럼 재생성한다.

```bash
gcc -O2 -Wall -Wextra -Wformat=2 -Werror -o /tmp/r4_ptrace_instruction_trace ptrace_instruction_trace.c
/tmp/r4_ptrace_instruction_trace 415440 100000 artifacts/lua_trace_two_adds_x9.csv ./lua_interpreter_fixture ./lua_chunk_two_adds.luac 9
python bytecode_handler_map.py artifacts/lua_trace_two_adds_x9.csv bytecode_handler_map_two_adds_x9.json lua_chunk_two_adds.luac
```

## 남은 범위

이번 합성은 **첫 handler 진입의 실제 경계 상태**에서 출발한다. 실행기 인자 `x`가 첫 VM 슬롯에 쓰이기까지의 전이와 마지막 VM 결과가 반환되는 전이는 아직 요약에 포함되지 않았다. 따라서 전체 프로그램을 시작 상태부터 끝까지 기호 실행했다고 주장하지 않는다. 정수 태그 fast 경로와 이 다섯 명령의 fetch 경로 밖도 `unknown`이며, 모든 가능한 별칭과 코드 변경에 대한 정적 증명은 없다. 연결 전이에는 `.luac` 위치 대응과 ELF 읽기 전용 점프 테이블이라는 대상별 binding이 필요하다. 또한 직렬화된 연결 요약은 약 68 KiB로, 여러 출력식에 공통 부분식이 반복된다. 더 긴 프로그램에서는 공유 SSA/DAG 표현과 캐시 비용 측정이 필요하다.

다음 작업은 입력 바인딩과 반환 전이를 같은 형식으로 붙여 실행기 인자에서 최종 결과까지 합성하고, 다른 산술 처리 구간에서도 같은 핵심 식·효과 평가기를 확인하는 것이다.
