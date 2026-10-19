# 세 엔진 통합 실험: 분기·호출·값, 문자열, 수명 효과

## 이번 묶음의 목표와 결과

Lua 5.4.8, CPython 3.13.5, Node 24.19.0 Ignition의 고정 바이너리와 고정 ABI에서, 같은 분기·함수 호출 예제를 각 엔진의 네이티브 실행 경로로 분석했다. 기존 증명에 사용하지 않은 입력 `42`의 추적을 새로 수집했다. 평가용 스크립트는 출력 대조에만 사용했고 네이티브 분석의 입력으로 파싱하지 않았다.

| 작업 | 이번 확인 | 판정 범위 |
|---|---|---|
| 분기·호출·반환 | 새 입력 `42`에서 세 엔진의 결과 `47`을 P-code 경로 증명으로 확인 | 관측한 경로와 명시한 진입 상태 |
| 저장된 숫자 구간 요약 | Python·JavaScript 각 한 구간에서 새 입력과 일치, 대상 P-code 재생 0회 | 저장된 구간의 guard·읽기·쓰기·후속 주소가 일치할 때만 적용 |
| Lua 숫자 구간 | 새 전체 경로를 다시 증명 | 이전에 저장한 Lua `+7` 구간과 경로가 달라 기존 요약 적용은 `unknown` |
| 공통 값 슬라이스 | 세 엔진 모두 같은 바이트 단위 P-code 슬라이서 실행 | 결과값의 후보 의존성 목록; 제어와 다른 효과의 제거 증명은 아님 |
| 공통 값 IL | `X=0 → 10`, `5≤X≤251 → X+5`를 증명서 기반으로 투영 | 제한된 인증서 문법 두 식에 대한 projection; 자동 P-code/SSA→IL 생성은 아님 |
| 문자열 길이 | JavaScript 네이티브 요약이 2자리·6자리의 새 추적에 일치; 12자리는 `unknown` | Lua·Python은 같은 출력 oracle만 비교, 네이티브 문자열 요약 미작성 |
| 할당 수명 | 이전 Lua/Python 제한 풀 증거를 별도로 유지; 새 Lua 풀에서 실패·GC·재시도 관찰 | 새 실패 경로는 allocator 관찰. 공통 네이티브 helper 요약 및 JS GC는 미증명 |

기계 판독 결과는 [통합 결과](integrated_pipeline_result.json), [값 IL](integrated_common_il.json), [선택된 P-code와 제외 감사](integrated_native_slice_42.json)에 있다. 실행기는 [run_integrated_pipeline.py](run_integrated_pipeline.py)이다.

## 값이 얼마나 줄었나

| 엔진 | 슬라이스 대상 구간의 네이티브 명령 | 해당 구간의 동적 P-code 연산 | 결과값 후보로 선택한 연산 | 선택된 네이티브 명령 |
|---|---:|---:|---:|---:|
| Lua | 281 | 2,195 | 19 | 9 |
| Python | 987 | 5,320 | 50 | 30 |
| JavaScript | 29,446 | 199,761 | 229 | 118 |

이 숫자는 같은 크기의 코드를 세 언어에서 최적화한 비율이 아니다. Lua의 구간은 VM 입력 읽기부터 결과값 쓰기까지이고 Python·JavaScript는 호출자 진입부터 복귀까지다. 선택된 연산도 실행 가능한 독립 프로그램은 아니다. 슬라이스는 관측된 LOAD/STORE 주소를 사용하며 주소 계산의 기호 의존성을 증명하지 않는다. JavaScript의 `cmovne`에는 내부 P-code 분기 의존성이 1건 남는다. 모든 경로 guard, 저장된 네이티브 효과, 호출·반환 증거를 버리지 않고 별도로 보존했다.

이번 IL의 읽기 쉬운 출력은 다음과 같다.

```c
if (X == 0) return 10;
if (5 <= X && X <= 251) return X + 5;
return unknown;
```

이것은 원본 함수의 모든 효과를 가진 C 코드가 아니라 **결과값 투영**이다. 관측된 자식 호출의 인수 `5` 또는 `X`는 Python·JavaScript 네이티브 증명서에서 가져왔고, Lua에서는 자식 handler 진입과 최종 값 식만 이번 인증서에 있다. 새 벤치마크 스크립트에서 0·9·42·251의 출력은 세 엔진 모두 이 IL과 같았다. `252`는 실제 출력이 같더라도 공유 증명 범위 밖이므로 `unknown`으로 남겼다.

Python의 새 추적은 입력 캐시 객체 `42`의 digit을 `X`로 기호화한다. `X=37`이면 계산된 결과 포인터가 바로 그 객체 `42`를 다시 가리키므로, 포인터 식만으로 숫자값을 증명할 수 없다. 따라서 **새 입력 42를 기준으로 한 값 증명은** `5≤X≤251 ∧ X≠37`에 한정했다. 기존 입력 객체 `9`를 기준으로 한 별도 증명의 비별칭 조건은 `X≠4`이며 공유 범위 `5..251`에서는 항상 성립한다. 이 두 고정 객체 모델이 곧 실제 CLI 입력 전체의 주소 변화 증명이라는 뜻은 아니다.

## 문자열과 실패 경로

JavaScript 문자열 루프의 저장된 요약은 새 숫자 문자열 `"42"`, `"234567"`의 전체 네이티브 상태 전이에 적용됐다. 두 경우 모두 Lua·Python·JavaScript 평가 프로그램의 출력은 각각 `"425"`, `"2345675"`였다. `"123456789012"`도 세 출력은 일치하지만 JavaScript의 저장된 길이·경로 schema를 벗어나므로 네이티브 요약은 적용하지 않았다. 변조한 JavaScript 네이티브 쓰기와 Python/JavaScript 숫자 구간의 변조 후속 주소는 모두 거절했다.

새 [Lua 실패·재시도 fixture](lua_pool_failure_retry_fixture.c)는 160바이트 슬롯 한 개에서 105바이트 객체를 유지한 채 121바이트 객체를 만들려고 한다. Lua의 메모리 오류 경로에서 allocator가 두 번 실패 응답을 내고, 보호 호출은 `LUA_ERRMEM`을 반환했다. 첫 객체의 루트를 제거하고 GC로 105바이트를 해제한 뒤, **새 보호 호출**에서 121바이트 객체가 같은 주소의 다음 세대로 생성됐다. [관측 기록](artifacts/integrated_lua_failure_retry.jsonl)의 효과 순서는 `Allocate, AllocationFailed, AllocationFailed, Free, Allocate, Free`다. 실패 중 live 상태가 바뀌거나, 세대가 오래되거나, 해제 크기가 틀리면 검사기가 거절한다. 이는 제어된 allocator 관찰의 검증이며, 이 새 바이너리의 실패 네이티브 경로 또는 공통 효과 코어 적용 증명이 아니다.

## 재현과 다음 연구 단위

현재 체크아웃의 고정 바이너리·원시 추적을 사용하는 재생 명령은 다음과 같다. Python 의존성은 `requirements-cross-language.txt`에 있다.

```bash
cd experiments/interpreter-expression
python -m venv /tmp/r4-integrated-venv
/tmp/r4-integrated-venv/bin/python -m pip install -r requirements-cross-language.txt
/tmp/r4-integrated-venv/bin/python prove_lua_full_flow.py
/tmp/r4-integrated-venv/bin/python prove_cross_full_flow.py
/tmp/r4-integrated-venv/bin/python run_integrated_pipeline.py
```

Lua 소스 5.4.8의 `liblua.a`를 다시 빌드한 환경에서는 `integrated_lua_runner.c`와 `lua_pool_failure_retry_fixture.c`를 같은 `gcc -O2 -fno-pie -no-pie` 옵션으로 링크할 수 있다. 결과 JSON은 바이너리와 추적 SHA-256을 검사한다. 새 추적을 수집하려면 기존 `trace_cross_full_flow.py`, `trace_js_holdout.py`, `prove_lua_full_flow.py`의 핀된 런타임·마커 설정이 필요하다.

다음 큰 연구 단위는 다음 세 연결을 묶는 것이다: (1) 고정 인증서 문자열 대신 SMT/P-code 식 AST와 호출·메모리 효과에서 IL을 생성, (2) LOAD/STORE 주소와 분기의 제어 의존성을 포함한 슬라이스 및 경계 자동 발견, (3) 새 Lua 실패 경로와 Python 예외 경로에 네이티브 효과 증명을 추가하고 12자리 이상 JavaScript 문자열 경로를 별도로 동결. 각 엔진에서 새 입력과 부정 입력을 유지하며 적용 가능성을 `적용/unknown/반례`로 판정해야 한다.
