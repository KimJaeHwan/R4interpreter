# CPython PyLong: 제한된 풀의 객체 수명 실험

## 질문과 실험 경계

[이전 할당 경로 실험](PYTHON_ALLOCATION_EFFECT_RESULT.md)은 네이티브 `Write`를 재현했지만, 새 객체의 수명과 주소 재사용을 판단할 근거가 없었다. 이번에는 CPython 3.13.5가 실제로 호출하는 `PyLong_FromLong`에 **범위가 명시된 객체 도메인 allocator**를 연결했다. 4개의 32바이트 슬롯을 가진 정적 풀에서 생성·해제·같은 주소 재사용·고갈을 관찰하고, 기존 [공통 구간 적용기](composed_native_transition.py)로 네이티브 상태 전이를 확인했다.

대상은 `PyMem_SetAllocator(PYMEM_DOMAIN_OBJ, ...)`를 설치한 [실험 실행 파일](python_pool_lifetime_fixture.c)에서 `scoped=1`로 감싼 `PyLong_FromLong` 호출뿐이다. 나머지 CPython 할당은 기존 allocator로 넘긴다. `free`와 `realloc`은 scope 밖에서도 풀 주소를 먼저 검사한다. 이 풀에 속하지 않는 일반 CPython 힙에 대한 소유권·freshness 증명은 없다.

처음 시도한 한 자리 정수 `257`은 CPython의 compact-int freelist 때문에 allocator hook 호출이 보이지 않았다. 그래서 이 실험은 두 자리 정수 `2^30` 이상을 사용한다. 실행 파일은 대상 호출마다 정확히 32바이트 요청 한 건인지 검사하며, 캐시 정수 `256`이 풀을 사용하지 않는 것도 확인한다.

## 만든 요약과 검증 단계

1. `r4_pool_transition(state, slot, op)`의 실제 x86-64 명령을 P-code로 재생해 성공한 할당·해제 경로를 [조건부 네이티브 요약](pool_native_transition_summary.json)으로 저장했다. 경로 guard, 16개 범용 레지스터, 플래그, 메모리 읽기, 순서 있는 쓰기, 반환 주소가 들어 있다.
2. [SMT 결과](pool_native_refinement_result.json)는 두 경로 × 4개 슬롯에서, 올바른 진입 상태라면 요약의 **전체 바이트 메모리 배열**이 추상 풀 상태 갱신과 같음을 확인했다. 성공 시 반환값 1, 세대 증가, live 비트 전환을 확인했고, 이미 사용 중인 슬롯의 재할당·이미 빈 슬롯의 해제·세대 오버플로는 성공 경로 guard에서 거부된다. 이 증명은 ABI, 상태 영역과 반환 스택의 비중첩, 유효한 live 비트, 각 성공 동작의 전제에 의존한다.
3. [수명 ledger](pool_lifetime_ledger.py)는 4개 슬롯이 처음에 모두 비어 있다는 조건 아래 각 `Allocate`, `Free`, `AllocationFailed` 이벤트를 순서대로 적용한다. 객체 정체성은 `(slot, generation)`이다. 같은 주소라도 세대가 달라지면 새 객체다. 객체 snapshot의 참조계수·타입 포인터·크기 태그·두 digit을 할당 이벤트에 연결한다. 이 연결은 실제 CPython hook과 출력의 **관측 검증**이며, CPython 전체 allocator 구현의 정적 증명은 아니다.
4. [적용 결과](pool_lifetime_application_result.json)는 고정한 요약을 소스 입력과 **그 뒤 수집한 두 입력**에 적용한 것이다. 대상 구간의 P-code를 다시 재생하지 않고 경로, 읽기, 쓰기, 종료 상태를 네이티브 trace에 대조했다. 각 helper 호출의 풀 상태를 다음 호출로 연결하고 ledger 이벤트와 비교했다.

| 실행 입력 | 성공 helper 호출 | 네이티브 명령 | 이벤트 | 객체 | 풀 고갈 | 주소 재사용 |
|---:|---:|---:|---:|---:|---:|---:|
| 1073741824, 요약 소스 | 10 | 215 | 11 | 5 | 1 | 슬롯 0, 세대 1→2 |
| 1073742000, 별도 입력 | 10 | 215 | 11 | 5 | 1 | 슬롯 0, 세대 1→2 |
| 1074741800, 별도 입력 | 10 | 215 | 11 | 5 | 1 | 슬롯 0, 세대 1→2 |

세 실행 모두 풀의 최종 live 비트는 0이다. 합계 30개 helper 호출에서 읽기 75건과 순서 있는 쓰기 45건이 저장된 요약과 일치했다. ledger는 빠진 이벤트, 슬롯 내부 포인터, 다른 요청 크기, 겹친 할당, 중복 해제, 잘못된 세대 재사용, 고갈 후 상태 변경, 잘못된 live 비트, 지난 세대 접근, 비활성 슬롯 접근, 범위 밖 접근, 세대 오버플로, 중복 객체 snapshot의 13가지 변조를 거부했다. 네이티브 증명의 실제 호출 조건에서는 상태·반환 스택 중첩, 잘못된 live 비트, 다른 반환 스택 값, 범위 밖 슬롯의 4가지 변조를 거부했다. Python의 앞선 TLS 상태 실험에서도 `FS_BASE`·`GS_BASE`를 구간 사이에 전달했고, 공통 적용기에 직접 주입한 변조 9종을 거부했다. [그 결과](python_core_validation_result.json)에는 별도 Python 입력 4개의 두 구간 연결도 있다.

## 공통 효과 형식에 주는 의미

이 실험에서 `Write(address, bytes)`는 실제 필드 갱신을 담당하고, 별도 ledger의 `Allocate(slot, generation, extent)`, `Free(slot, generation)`, `AllocationFailed`가 **소유권과 수명**을 설명한다. 두 층을 연결하려면 할당자 경계, 정확한 요청 크기, 풀 초기 상태, 슬롯 비중첩, 실패 경로가 필요했다. 지금의 공통 요약 코어에는 수명 이벤트가 아직 내장되지 않았다. 다음 구현 단계는 이 이벤트와 근거 수준을 공통 형식의 효과로 추가하고, 현재 ledger가 외부에서 하는 검사를 적용기 내부의 조합 규칙으로 옮기는 것이다.

실제 CPython 경로의 `PyLong` 생성 전체를 정적으로 증명한 결과는 아니다. 네이티브로 증명한 대상은 실험용 풀 상태 helper의 성공 경로이고, hook 호출·객체 필드·실패 시 예외는 고정 CPython 라이브러리에서 관찰했다. trace 수집 시 자식 프로세스의 메모리 매핑에서 로드된 `libpython3.13.so.1.0`의 경로·장치·inode를 파일과 대조하고 SHA-256을 기록했다. 저장 trace를 적용할 때는 기록된 해시와 현재 라이브러리의 해시를 비교한다. 다른 크기, 일반 allocator, 다른 Python 버전, 예외 생성의 네이티브 전체 경로는 이 결과 밖이다. 최초 읽기 메모리와 실행 경로는 대상 trace에서 제공한다.

## 재현 순서

저장소 루트에서 실행한다. 실행 파일은 기록된 `libpython3.13.so.1.0`이 설치된 x86-64 환경을 사용한다. ptrace가 허용되어야 새 trace를 만들 수 있다.

```bash
gcc -O1 -g -fno-omit-frame-pointer -fno-stack-protector -fno-pie -no-pie -Wall -Wextra -Werror experiments/interpreter-expression/python_pool_lifetime_fixture.c -Wl,-l:libpython3.13.so.1.0 -o experiments/interpreter-expression/python_pool_lifetime_fixture
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_python_pool_lifetime.py 1073741824 experiments/interpreter-expression/artifacts/python_pool_source.json.gz
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/freeze_pool_lifetime.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_python_pool_lifetime.py 1073742000 experiments/interpreter-expression/artifacts/python_pool_holdout_1073742000.json.gz
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_python_pool_lifetime.py 1074741800 experiments/interpreter-expression/artifacts/python_pool_holdout_1074741800.json.gz
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/apply_pool_lifetime.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/verify_python_composed_core.py
```

`freeze_pool_lifetime.py`를 실행한 뒤 별도 입력 trace를 수집해야 요약 재사용 검사가 된다. 저장된 JSON에는 실행 파일과 라이브러리 해시가 들어 있으며, 적용기는 현재 바이너리와 일치하지 않으면 거부한다.
