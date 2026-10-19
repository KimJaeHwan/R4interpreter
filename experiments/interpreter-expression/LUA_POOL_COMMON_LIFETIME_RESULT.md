# 두 번째 엔진: Lua 문자열의 공통 수명 효과

## 질문과 실험 경계

CPython 제한 풀에서 만든 `Allocate`·`Free` 공통 수명 효과를 **Lua 5.4.8의 실제 allocator 요청과 GC 해제**에도 적용할 수 있는지 확인했다. [공통 코어](common_lifetime_effects.py)와 [네이티브 구간 합성기](composed_native_transition.py)의 효과 규칙은 바꾸지 않았다. Lua 어댑터가 엔진별 allocator 연결, 고정 요청 크기, 객체 데이터 관측을 맡는다. [기존 Python helper 적용기](apply_pool_lifetime.py)에는 domain 인자만 추가했고 기본값과 기존 결과는 유지했다.

Lua는 `lua_newstate`에 전달한 allocator를 호출한다. [실험 ELF](lua_pool_lifetime_fixture.c)는 80바이트 **긴 문자열**을 `lua_pushlstring`으로 만든다. 해당 Lua 빌드의 요청 크기는 문자열 객체 헤더와 끝 바이트를 포함한 **105바이트**다. 생성 호출의 정확히 한 요청만 4개 정적 슬롯(각 128바이트)에 배정한다. 다른 Lua 요청은 libc allocator로 보낸다. 슬롯의 해제는 scope 밖에서도 포인터로 식별하고, 그때 Lua가 전달한 `osize=105`를 직접 확인한다. 풀이 소유한 포인터에 대한 재할당은 예상 밖 경로로 거부한다. 슬롯 시작 주소와 `lua_tolstring` 데이터 주소의 차이 24바이트는 이 고정 빌드에서 관측·대조한 값이다.

두 문자열을 Lua stack에 root한 뒤 첫 root만 제거하고 `lua_gc(L, LUA_GCCOLLECT)`를 호출했다. 실제 allocator의 `free`가 발생한 다음 새 문자열이 같은 슬롯 주소를 받는다. 다른 root의 내용은 유지되고, 마지막 root들을 제거·수집하면 live mask가 0이 된다. C 변수의 데이터 포인터는 Lua GC root로 취급하지 않는다.

## 분석 결과

`r4_pool_transition`의 할당·해제 두 네이티브 경로를 이 Lua ELF에서 새로 추적하고 Ghidra P-code로 올려, 유효한 ABI·풀 상태·비중첩 전제 아래 **전체 byte-memory frame과 반환값**을 슬롯별 SMT로 검사했다. 2개 경로 × 4개 슬롯의 모든 반례 질의가 `unsat`였다. [고정 구간 요약](lua_pool_native_transition_summary.json)과 [증명 결과](lua_pool_native_refinement_result.json)는 먼저 소스 입력 0으로 만들었다. 그 뒤 서로 다른 문자열 바이트의 입력 1, 2를 새 프로세스에서 수집했다. 입력 2의 두 번째 문자열에는 중간 NUL 바이트가 있다.

| 입력 | 성격 | 네이티브 helper | 공통 효과 | 할당 / 해제 | 최종 live |
|---|---|---:|---:|---:|---:|
| 0 | 요약 소스 | 6 | 6 | 3 / 3 | 0 |
| 1 | 별도 입력 | 6 | 6 | 3 / 3 | 0 |
| 2 | 별도 입력, 중간 NUL | 6 | 6 | 3 / 3 | 0 |

[적용 결과](lua_pool_common_effect_application_result.json)는 18개 효과의 원시 trace·네이티브 요약·증명 해시, 슬롯·요청 크기·세대와 실제 allocator 이벤트 대조를 저장한다. 슬롯 0은 첫 문자열과 세 번째 문자열에 같은 주소를 줬지만 정체성은 `(controlled_lua_string_pool, pool_slot_0, 1)`과 `(controlled_lua_string_pool, pool_slot_0, 2)`로 나뉜다. 이전 세대 접근은 공통 코어에서 거부됐다. 문자열의 길이·내용 해시를 입력에서 독립적으로 계산하여 `lua_tolstring` 관측과 대조했다. 9개 직접 부정 검증에는 요청 크기 변조, live 슬롯 중복 할당, 선행 해제, 잘못된 세대, native/lifetime 진입 불일치, 동결 효과 크기 변조·누락, GC free 이벤트 누락, allocator 요청 관측 변조가 들어 있다. 예상 밖 풀 재할당과 대상 scope의 추가 할당은 fixture에 거부 분기를 구현했지만 이 9개 검증에서 해당 분기를 직접 실행하지 않았다. 기존 CPython 공통 효과 적용도 다시 실행해 **3건·30 helper·33 효과·18 거부**를 유지했다.

## 무엇이 증명되고 무엇이 관측됐나

- **조건부 네이티브 증명:** 풀 상태 helper의 두 성공 경로, 전체 메모리 갱신, 반환값. 성공 `Allocate`/`Free`는 이 helper의 반환 지점에서 공통 효과와 합성했다. Lua 내부의 문자열 생성 전체나 GC 전체를 SMT로 증명한 결과는 아니다.
- **관측된 연결:** 정확한 Lua allocator 호출, 105바이트 요청, Lua 문자열 데이터와 풀 객체 시작 주소, GC가 호출한 해제, 주소 재사용과 남은 root의 내용. 정적 풀 초기 소유권은 fixture가 선언한 계약이다.
- **미검증:** 일반 Lua 힙의 소유권·GC 도달성, 다른 문자열 길이·짧은 문자열, 풀 포인터 재할당, 할당 실패와 Lua의 재시도, 임의의 엔진 경로. 특히 이 실험에서는 `AllocationFailed`를 만들거나 성공 helper 증명을 실패에 붙이지 않았다. 예상 밖 요청은 범용 효과로 추측하지 않고 거부한다.

따라서 교차 엔진에서 재사용된 것은 **수명 효과의 의미·검증 코어·네이티브 구간 적용 형식**이다. Lua allocator 경계와 GC 이벤트를 찾아 연결하는 어댑터는 여전히 필요하다.

## 재현

저장소 루트에서 실행한다. 현재 ELF는 Lua `v5.4.8` 커밋 `6e22fedb74cf0c9b6656e9fce8b7331db847c605`의 `liblua.a`(SHA-256 `e186750bbe99b41f9f40d993d1a8f751bf0fc6a5f72763d260fd1d5dcfac9172`)를 정적으로 링크했다. Lua 소스가 `/workspace/scratch/lua-5.4.8`에 있다면 아래 빌드가 현재 ELF를 재현한다. 빌드를 다시 하면 ELF 해시와 주소가 바뀔 수 있으므로 trace·요약·증명도 순서대로 다시 만든다.

```bash
cd experiments/interpreter-expression
gcc -O2 -g -fno-pie -no-pie -Wall -Wextra -I/workspace/scratch/lua-5.4.8 lua_pool_lifetime_fixture.c /workspace/scratch/lua-5.4.8/liblua.a -lm -ldl -o lua_pool_lifetime_fixture
../../experiments/vm-transition-testbed/.venv/bin/python trace_lua_pool_lifetime.py 0 artifacts/lua_pool_source.json.gz
../../experiments/vm-transition-testbed/.venv/bin/python freeze_lua_pool_lifetime.py
../../experiments/vm-transition-testbed/.venv/bin/python trace_lua_pool_lifetime.py 1 artifacts/lua_pool_holdout_1.json.gz
../../experiments/vm-transition-testbed/.venv/bin/python trace_lua_pool_lifetime.py 2 artifacts/lua_pool_holdout_2.json.gz
../../experiments/vm-transition-testbed/.venv/bin/python apply_lua_pool_effects.py
```

실험에 사용한 ELF·세 trace·고정 요약·증명·결과는 저장소에 함께 보관한다. 다음 경계 실험은 Lua에서 크기가 다른 요청이나 allocator 실패·재시도를 추적해 현재 `unknown`을 분리하는 것이다. 이후 CPython의 실패 경로에도 별도 네이티브 요약을 붙여, 관측 효과와 증명 효과가 어디까지 확장되는지 비교한다.
