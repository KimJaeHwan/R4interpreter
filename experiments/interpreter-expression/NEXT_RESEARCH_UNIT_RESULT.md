# 공통 AST-IL, 주소·제어 의존성, 새 경로 연구 단위

## 판정

고정된 Lua 5.4.8, CPython 3.13.5, Node 24.19.0 바이너리와 기록된 네이티브 경로에 대해 다음을 확인했다. 평가용 원본 스크립트는 출력 oracle이고, IL의 식은 저장된 네이티브 P-code 전이에서 읽는다.

| 연결 | 결과 | 아직 열려 있는 경계 |
|---|---|---|
| 전이식 AST→공통 typed IL | Lua 23명령·85노드, Python 116명령·795노드, JS 숫자 23명령·226노드, JS 긴 문자열 182명령·1,466노드. guard, read 주소, 순서 있는 write 주소·값, 출력, 다음 주소의 모든 루트 270개가 원래 SMT 식과 각각 `unsat` 동등성 판정. 각 다음 주소 변조는 `sat`로 검출 | 저장된 경로 식의 구조 변환 증명이다. 원본 스크립트 복원, 호출 의미 자동 발견, 새 경로 완전성 증명은 아니다 |
| 주소·제어 의존성 | 새 입력 `42`의 기존 값 슬라이스 19/50/229개 연산을 각각 545/1,759/80,192개 의무로 확장. Lua/Python/JS에 각각 1/1/18개 미해결 묶음 | 엔진별 구간 길이가 달라 수치를 엔진 사이 절감률로 비교할 수 없다. 관측된 주소를 사용하며 효과 삭제를 허용하지 않는다 |
| JS 긴 문자열 | 12자리 원천의 182명령, 읽기 45개, 쓰기 28개를 동결. 별도 12·17·18자리 3건에서 전체 저장 전이 일치, 대상 P-code 재생 0회. 11·19자리와 변조 3건은 `unknown` | 입력 객체의 문자 바이트는 네이티브 진입에서 별도로 캡처했다. 이 구간은 cons 문자열 포인터를 만들며 GC·flattening·최종 직렬화는 미포함 |
| Lua 실패·재시도 | allocator의 성공·두 실패·해제·재성공·해제 6개 절단점을 94·95자리 새 실행에서 각각 재사용, 총 12개 절단점·508명령. 공통 수명 ledger에 `Allocate, AllocationFailed, AllocationFailed, Free, Allocate, Free`를 합성, 두 실행 모두 세대 2·최종 미소유. 쓰기·다음 주소·상태·인수 변조 5종 거부 | 실패 시 소유 상태 불변 및 성공·해제 상태식은 **관측 경로 guard와 비중첩 스택 범위** 아래 SMT 증명. Lua `LUA_ERRMEM` unwind 전체는 미요약 |
| CPython 예외 접점 | 독립 값 2개에서 풀 소진 지점, allocator NULL, `PyLong_FromLong` NULL, `PyErr_Occurred`의 비NULL 반환 등 5개 절단점을 관측 | 사이의 libpython 명령, 구체적인 예외 타입, 일반 CPython 힙은 아직 요약·증명하지 않았다 |

기계 판독 결과: [AST-IL](native_ast_il_result.json), [주소·제어 의무](address_control_slice_result.json), [JS 적용](js_long_string_application_result.json), [Lua 네이티브 조건부 증명](lua_allocator_failure_native_proof.json), [Lua 공통 수명 적용](lua_allocator_common_lifetime_result.json), [Python 예외 접점](python_exception_boundary_result.json). 전체 식 DAG는 [native_ast_il.json](native_ast_il.json)에 저장했다.

## 왜 이 구분이 필요한가

값만 역추적하면 “무엇을 계산했는가”의 후보를 얻는다. 그러나 계산된 주소가 다른 위치를 가리키거나, 다른 분기가 실행되거나, 중간 쓰기가 사라지면 같은 숫자 결과라도 실제 VM 상태는 달라진다. 따라서 IL은 읽기 주소, 순서 있는 쓰기, 분기 조건과 다음 주소를 같이 담는다. 슬라이스의 `debt`는 버려도 되는 연산 목록이 아니라 추가 증명이 필요한 의무다.

Lua의 실패 분기에는 `live`·`generation`·`live_extent`에 대한 직접 쓰기가 없다. 하지만 스택 포인터를 아무 주소나 허용하면 스택 저장이 전역 소유 상태와 겹칠 수 있다. `0x100000000 < RSP < 0x800000000000`의 고정 ELF 스택 범위에서만 세 전역 쓰기의 부재가 `unsat`가 된다. 성공 증명에는 요청 크기 1..160과 세대 overflow 부재도 필요하다. 이 전제는 재사용 판정에 포함되어야 한다.

Lua 적용기는 각 allocator 절단점의 실제 `RSI/RCX/RDX` 인수를 이벤트에 묶고, 전후 `live/generation/live_extent` 메모리를 공통 ledger와 대조한다. 계산된 네이티브 쓰기의 종료 값도 실제 절단점 메모리와 비교한다. 따라서 개별 경로가 맞더라도 서로 다른 수명 상태의 경로를 임의로 잇는 적용은 거부한다. 공통 효과의 `helper_return`은 이 fixture에서 검증한 allocator 함수의 반환 절단점을 가리킨다. 해제 직후 접근과 같은 주소의 세대 2 재할당 뒤 세대 1 접근을 각각 거부했다.

JS 긴 문자열은 앞선 2..11자리의 문자 복사 경로와 다르다. 12자리부터 관측한 경로는 원본 문자 바이트를 해당 handler 안에서 전부 읽지 않고 cons 문자열을 구성한다. 진입 객체의 바이트 snapshot 없이는 handler의 조건과 결과를 입력 문자열에 묶을 수 없다. 실험은 12..18자리만 적용하고 19자리는 같은 네이티브 모양이어도 입력 계약 밖이라 `unknown`으로 둔다.

## 재현 순서

기존 원시 추적과 고정 바이너리를 사용하는 명령이다. Python 환경에는 `requirements-cross-language.txt` 의존성이 필요하다. `DAASDMLKAS_REPO`는 이전 역방향 슬라이스 실험에만 필요하며 그 저장소는 수정하지 않는다.

```bash
cd experiments/interpreter-expression
python freeze_js_long_string.py
python apply_js_long_string.py
python freeze_lua_allocator_paths.py
python apply_lua_allocator_paths.py
python native_ast_il.py
python run_integrated_pipeline.py
python analyze_dependency_slice.py
python probe_python_exception_boundary.py
```

원시 추적을 새로 수집하려면 `trace_js_holdout.py --string`과 `trace_lua_allocator_failure.py --length 94|95|96`을 각각 고정된 Node/Lua 바이너리에 실행한다. 추적 파일 SHA-256, 실행 파일 SHA-256, fixture SHA-256, 진입 상태, 순서 있는 쓰기, 후속 주소가 적용 경계에 들어간다. Python 절단점 스크립트는 고정 ELF와 libpython 해시를 먼저 검사한다.

## 다음 판단

가장 큰 남은 연구는 동적 경로의 자동 경계 발견과 실제 주소 별칭·제어 의존성의 폐쇄다. 그다음 CPython 오류 전파 구간과 Lua `LUA_ERRMEM` unwind를 효과 요약에 연결할 수 있다. 현재 AST-IL의 노드 수는 **네이티브 전이의 표현 크기**이며 원본 스크립트 크기로 줄였다는 수치는 아니다. 그 축약은 상태/효과를 보존한 채 별도 의미 투영으로 검증해야 한다.
