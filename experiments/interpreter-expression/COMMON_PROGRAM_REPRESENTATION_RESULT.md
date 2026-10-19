# 공통 프로그램 표현 IL: 검증된 범위

`common_program_representation_v1.json`은 Python·Lua·JavaScript에서 검증한 여섯 네이티브 단위, Lua의 입력→출력 값 전달 체인 일곱 개, 제어된 풀 두 종류의 수명 효과를 같은 증거 포함 형식으로 표현한다. 작은 `BV32`·`BV64` 값 DAG는 평가할 수 있다. 네이티브 노드는 저장된 가드·효과, 관측 원장, 검증 증명서와 실제 평가기 참조를 함께 갖지만 이 JSON만으로 독립 실행되지는 않는다.

Python의 네 단위는 각 입력의 **전체 관측 네이티브 경로**이다. Lua와 JavaScript는 각각 **한 핸들러 구간**이며 호출자에서 함수 반환까지의 경로로 합성한 것이 아니다. 모든 입력·환경·분기·예외를 포괄하는 프로그램은 아직 아니다.

별도의 Lua 분기·함수 호출 바이트코드에서는 `run_lua_chunk`의 인수 `X`에서 `printf`의 두 번째 인수까지 `X == 0 ? 10 : (X+5) mod 2^64` 값 전달을 연결했다. 기존 여섯 입력 `0`, `9`, `1`, `-1`, `INT64_MAX`, `INT64_MIN`의 증명을 다시 실행했고, 이전 통합 실험의 원시 추적만 있던 입력 `42`에는 같은 증명을 새로 적용해 출력 `47`을 확인했다. VM 안의 연속된 구간은 0 경로에서 237명령·20개 조건분기·호출 1개, 나머지 경로에서 각각 281명령·24개 조건분기·호출 2개다. 각 경로의 반대 분기 3개는 다른 저장 추적에서 실제로 관측됐으며, 남은 반대 분기와 예외는 미해결이다. 긴 중간 구간은 특정 값 슬롯의 쓰기 감사와 하드웨어 감시로 연결한다. `luaL_newstate`를 건너는 RBP 보존에는 x86-64 SysV ABI 가정과 관측 입력 확인이 포함된다. 하드웨어 감시는 **해당 관측 실행**의 슬롯 보존 근거다. 긴 구간의 **전체 레지스터·메모리 상태 전이**는 계산하지 않았으며 `UnknownNativeStateAcrossGap`으로 남긴다.

| 단위 | 적용 범위 | 네이티브 명령 | 노드 | 미해결 의무 |
|---|---|---:|---:|---:|
| python_251 | selected_full_native_path | 987 | 6 | 131 |
| python_252 | selected_full_native_path | 1017 | 6 | 139 |
| python_254 | selected_full_native_path | 1017 | 6 | 139 |
| python_255 | selected_full_native_path | 1017 | 6 | 139 |
| lua_segment | single_handler_segment | 23 | 1 | 3 |
| javascript_segment | single_handler_segment | 23 | 1 | 5 |

## 표현 예

```text
value library: BV32 Y := X + 5  (각 언어 어댑터가 증명한 입력 영역에서만)
Python exact witness: PcodeWindow -> CheckedExternalEffect(libc zero8) ->
  PcodeWindow -> GuardedNativeTransition -> GuardedNativeTransition -> PcodeWindow
Lua exact segment: GuardedNativeTransition -> UnknownEnclosingProgram
JavaScript exact segment: GuardedNativeTransition -> UnknownEnclosingProgram
Lua branch-call value chain: InputBinding -> PcodeValueTransfer ->
  AuditedNoWriteBridge -> PcodeValueTransfer -> AuditedNoWriteBridge ->
  GuardedPcodeValuePath -> PcodeValueTransfer -> AuditedNoWriteBridge ->
  PcodeValueTransfer(printf RSI)
각 단위: UnknownEdge / UnknownExceptionEdge / UnknownLifetime (해당할 때)
```

Lua의 선택된 `plus11` 핸들러와 새 분기·함수 호출 값 체인은 **서로 다른 바이트코드·경로**라 합성하지 않았다. 기존 `BV32 X+5` 값 라이브러리도 각각의 Lua·Python·JavaScript 어댑터가 증명한 영역에서만 사용한다. 새 Lua 체인은 별도 `BV64` 조건식이다. Python 경로의 출력 값은 네 정확한 입력에서 계산으로 확인했으며, 객체 할당 권한과 새 객체 여부는 별도 미해결 의무다.

## 수명 효과의 적용 범위

| 제어된 실험 도메인 | 검증 실행 | 논리 효과 | 근거 |
|---|---:|---:|---|
| Python `controlled_obj_pool` | 3 | 33 | 정적 예약 슬롯의 소유권, 네이티브 helper refinement, 관측 객체·할당 사건 |
| Lua `controlled_lua_string_pool` | 3 | 18 | 정적 예약 슬롯의 소유권, 네이티브 helper refinement, 관측 문자열·GC 해제 |

두 결과를 기존 일반 Python·Lua 실행 경로에 **붙이지 않았다**(`attached_to_program_routes=[]`). 실제 기본 allocator의 소유권·freshness·GC 수명을 이 제어된 풀 실험만으로 승인할 수 없기 때문이다. JavaScript 힙 수명도 아직 미해결이다. 효과의 `Allocate`·`Free`·`AllocationFailed`는 각 실험 도메인의 자원 ID와 세대를 포함한다. Python 풀의 할당 실패는 관측 allocator 사건이며 성공 helper처럼 네이티브 refinement가 증명한 효과가 아니다.

libc 노드는 특정 libc 이미지의 12개 명령과 `RDX=8`, `RSI=0`, 페이지·별칭·스택 전제를 검사한 후 목적지의 **정확히 8바이트**를 0으로 기록한다. 반환 레지스터와 정의된 플래그를 적고, 정의되지 않은 PF 및 벡터·마스크 레지스터의 후속 값은 미해결로 둔다. Python 구간 연결의 `computed` 등급은 이 정확한 입력과 첫 읽기 메모리 환경에만 적용한다.

생성기는 원시 추적에서 Python 메모리 원장과 제어 목록을 다시 만들고, 기존 경로 IL의 조건부 증명서를 검증한 다음 Python 네 경로를 재적용한다. Lua·JavaScript 요약은 각각 저장된 대상 추적에 다시 적용한다. Lua 값 체인은 기존 증명 함수 세 개와 VM 구간의 명령 디코딩·메모리 원장·제어 목록을 다시 검사한다. 두 제어된 풀은 **저장된 SMT refinement 결과의 해시·결론을 확인**하고 효과 적용기·거부 사례를 다시 실행한다. 별도로 `freeze_pool_lifetime.py`와 `freeze_lua_pool_lifetime.py`를 실행해 각각 2개 구간·8개 슬롯 사례의 SMT 증명이 다시 통과했고 저장된 증명 파일도 변하지 않았다. 저장된 JSON의 검증은 **같은 실행에서 원본으로 새로 만든 canonical**과 전체 비교하며, 가드·효과·출처·영역·수명 미해결 의무, ABI 가정, 감시 범위, 풀 도메인·효과 변조 등 24가지를 거부한다. 해시 자체를 의미 증명으로 취급하지 않는다.

재현:

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_common_program_representation.py
```

## 전체 로직 복원까지 남은 일

- 현재 선택 경로 밖의 분기·호출·예외를 찾고 실행 가능성 또는 불가능성을 증명한다.
- 일반 인터프리터 allocator의 할당·해제·객체 별칭과 수명 효과에 대한 권한을 확보한다. 제어된 풀의 권한을 전용할 수 없다.
- Lua 값 체인의 긴 간격에서 전체 네이티브 상태 전달을 확인하고, JavaScript의 핸들러 앞뒤 호출자 경로와 더 넓은 입력·환경을 연결한다.
- 검증된 CFG와 효과를 결합해 읽을 수 있는 전체 로직을 출력한다.
