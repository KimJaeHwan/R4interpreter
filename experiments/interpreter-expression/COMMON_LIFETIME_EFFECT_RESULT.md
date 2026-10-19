# 공통 수명 효과: 제한 풀에서 `Allocate`·`Free`·할당 실패 합성

## 무엇을 바꿨나

[앞선 CPython 제한 풀 실험](PYTHON_POOL_LIFETIME_RESULT.md)은 실제 네이티브 `Write`와 별도 Python 풀 ledger를 나란히 검증했다. 이번에는 [언어 중립 수명 코어](common_lifetime_effects.py)에 객체 소유 상태와 세 가지 효과를 넣고, [공통 네이티브 구간 적용기](composed_native_transition.py)가 **바이트 메모리 전이와 수명 전이를 함께 반환**하도록 연결했다. CPython 어댑터는 풀의 4개 슬롯·32바이트 배치, helper ABI, 실제 allocator 이벤트와 `PyLong` snapshot만 연결한다.

정체성은 `(domain_id, resource_id, generation)`이다. 같은 주소를 다시 받아도 generation이 바뀌면 새 객체가 된다. 각 자원에는 주소 공간, 소유 domain, 시작 주소, 요청 크기, 수용 크기, 정렬, live 상태가 있다. 코어는 다른 domain의 예약 영역도 같은 주소 공간에서 겹치면 거부한다. 객체 접근에는 **요청 크기**를 사용하고, 자원의 수용 크기를 접근 가능 범위로 확대하지 않는다.

[고정 네이티브 요약](pool_native_transition_summary.json)의 할당·해제 구간에는 버전 있는 `logical_effect` 하나를 각각 추가했다. 효과는 helper 반환 지점에 적용된다. 요약의 레지스터 입력에서 자원을 고른 뒤, 이전 수명 상태에서 주소와 generation을 계산한다. 대상 trace에 기록된 이벤트 값은 **계산 입력이 아니라 대조 대상**이다. 네이티브 검증 또는 수명 검증 중 하나라도 실패하면 새 상태를 반환하지 않는다. 수명 효과를 선언하지 않은 구간을 수명 상태와 합성하려 하면 `unknown`으로 거부한다.

`AllocationFailed`는 별도의 **관측 효과**다. 이번 풀 고갈에는 성공 helper의 네이티브 구간이 없으므로, 해당 네이티브 증명을 붙이지 않았다. 제한 풀 어댑터가 네 슬롯 모두 live이고 요청이 정확히 32바이트인지 확인한다. 효과는 새 객체 정체성을 만들지 않고 소유 상태를 그대로 둔다. 일반 allocator에서 실패하는 모든 이유를 공통 코어가 추측하지 않는다.

## 결과

| 대상 | 네이티브 성공 helper | 공통 수명 효과 | `Allocate` / `Free` / 실패 | 최종 live |
|---|---:|---:|---:|---:|
| 요약 소스 `1073741824` | 10 | 11 | 5 / 5 / 1 | 0 |
| 별도 입력 `1073742000` | 10 | 11 | 5 / 5 / 1 | 0 |
| 별도 입력 `1074741800` | 10 | 11 | 5 / 5 / 1 | 0 |

[적용 결과 JSON](common_pool_effect_application_result.json)에 33개 효과 각각과 근거 수준을 기록했다. 슬롯 0의 주소는 첫 객체와 재할당 객체에서 같지만 정체성은 `(controlled_obj_pool, pool_slot_0, 1)`과 `(controlled_obj_pool, pool_slot_0, 2)`로 분리됐다. 이전 generation의 접근은 거부됐다. 3개의 고갈 효과에는 `native_refinement_sha256`을 넣지 않았고, 각 효과의 전후 소유 자원이 완전히 같은지도 확인했다.

18개 부정 입력을 거부했다. 중복 할당, 할당 전 해제, 잘못된 자원·주소·크기, generation overflow, domain 간 주소 중첩, 요청 범위 밖 접근, 효과 누락·변조, 잘못된 증명 참조, 바뀐 효과 순서와 원자성, native 상태와 수명 상태의 불일치, 실패 효과에 성공 helper 증명을 잘못 붙이는 사례가 포함된다. 기존 제한 풀 결과도 유지됐다. Python의 FS/GS 두 구간 4건·직접 부정 입력 9건, 이전 PyLong 경로 4건 일치·1건 `unknown`, Lua 6건 일치, JavaScript 문자열 10건 일치·5건 `unknown`을 다시 확인했다.

## 근거와 남은 범위

- 성공한 풀 상태 helper의 **네이티브 전체 바이트 메모리 갱신**은 [기존 SMT 결과](pool_native_refinement_result.json)의 ABI·비중첩·유효 live 상태 등의 전제 아래 2개 경로 × 4개 슬롯에서 증명했다. 공통 효과가 그 전이와 일치하는 것은 이번 어댑터가 각 실행에서 검사했다. 공통 Python 코드 자체의 수학적 정당성을 SMT로 새로 증명한 결과는 아니다.
- helper가 실제 CPython allocator hook의 요청과 대응하는지, 객체 필드가 초기화됐는지, 실패 시 예외가 생기는지는 고정 CPython 라이브러리의 **관측 근거**다. 정적 풀의 초기 소유권은 실험 fixture의 계약이다.
- 공통 수명 코어의 현재 범위는 단일 스레드의 유한한 예약 자원이다. 각 helper의 바이트 메모리는 대상 trace의 최초 읽기 상태에서 시작하고, helper 사이에는 검증된 풀 상태와 수명 상태를 전달한다. CPython의 helper 사이 전체 바이트 메모리를 합성한 결과는 아니다. 일반 CPython 힙, 이동 GC, 재할당, 다른 크기, 설명되지 않은 호출·수명 프레임, 실패 경로의 네이티브 바이트 전이는 아직 `unknown`이다. Lua·JavaScript의 기존 구간에는 수명 효과가 없으며 이번 변경으로 그 엔진들의 객체 할당을 분석했다고 주장하지 않는다.

## 재현

저장소 루트에서 아래 순서로 실행한다. 실험용 CPython 3.13.5 라이브러리와 ptrace가 필요하다. 논리 효과가 포함된 요약을 고정한 **뒤** 별도 입력 trace를 수집한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/freeze_pool_lifetime.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_python_pool_lifetime.py 1073742000 experiments/interpreter-expression/artifacts/python_pool_holdout_1073742000.json.gz
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_python_pool_lifetime.py 1074741800 experiments/interpreter-expression/artifacts/python_pool_holdout_1074741800.json.gz
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_common_pool_effects.py
```

다음 실험은 이 효과를 다른 엔진의 **실제 할당 경계**에 적용하거나, CPython 고갈/예외 경로 자체의 네이티브 요약을 추가해 관측 효과의 범위를 줄이는 것이다.
