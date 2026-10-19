# 계산 상태로 연결한 Python 경로 적용기

## 이번 연구 단위의 결론

고정된 `/usr/bin/python3.13`와 같은 `branchCall(x) → addFive(x)` bytecode에서 `251·252·254`의 기존 전체 추적, 별도 저장된 `255` 전체 추적을 [공통 노드 적용기](common_path_executor.py)에 넣었다. 네 경로 모두 6구간을 **계산된 스칼라 상태와 바이트 메모리**로 연결해 마지막 반환 객체 포인터까지 일치했다. 할당 결과의 계산된 객체 digit과 고정 캐시 레이아웃도 각각 `X+5`와 대조했다. `255`는 기존 세 경로의 [경로 IL](evidence_program_path_il.json)에 포함하지 않았던 입력이다. 이 결론은 선택된 네 실행의 경로 모양과 최초 읽기 메모리를 입력으로 받는 조건부 결과다.

| 연결 구간 | 검증 방법 | 남은 범위 |
|---|---|---|
| 호출자 앞 513명령 | 고정 ELF에서 P-code 재생, 가드·읽기·순서 있는 쓰기·종료 GPR/플래그 대조 | 다른 분기 모양 |
| libc 12명령 | [고정 libc 계약](bounded_memset_contract.py)으로 반환 GPR·정의된 플래그·8바이트 0 쓰기 계산, 12명령 전체의 코드·접근 대조 | 다른 libc, 크기, 마스크 경로, vector/mask live-out |
| 호출자 뒤 158명령 | libc의 **계산 결과**를 입구로 P-code 재생 | 다른 호출 결과 |
| 숫자 116/146명령·다음 94명령 | 앞 구간의 계산 메모리·상태를 기존 동결 요약에 직접 전달 | 새 요약 경로, 기본 allocator 소유권 |
| 반환 94명령 | 두 동결 전이의 계산 결과로 P-code 재생, 반환 포인터 확인 | 다른 반환·예외 경로 |

libc 계약은 현재 환경의 `/lib/x86_64-linux-gnu/libc.so.6` SHA-256 `9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92`를 고정한다. 첫 PC의 파일 오프셋 `0x17c080`부터 실제 선택된 12명령의 ELF 바이트 전체와 Capstone 디코딩 결과를 확인한다. `RDX=8`, `RSI=0`, 목적지의 페이지 내 오프셋 `≤0xfc0`, 주소 범위 비겹침, 계산된 스택 반환 주소 `0x56004d`에만 적용한다. 12명령 전체의 메모리 접근을 검사하고 8바이트 저장 **이후**의 메모리에서 반환 주소를 다시 읽어 대조한다. `BZHI(-1,8)`의 하위 8비트가 마스크가 되므로 8바이트 모두 쓰기 범위다. 그중 2바이트는 이전 값도 0이지만 **같은 값 쓰기**로 보존한다. 추적기의 64바이트 읽기 표기와 달리 명령 의미에서 쓰기 크기를 8바이트로 계산한다. PF는 미정 기호로 두고, 뒤 P-code가 이를 사용해 출력에 영향을 주면 검증이 통과하지 못하게 했다. 스칼라와 바이트 메모리 외의 AVX 벡터·마스크 상태는 이 적용기의 상태 형식에 없다.

[적용기](apply_bounded_python_program.py)는 실행 초기에 전체 경로에서 최초로 읽힌 바이트만 환경 입력으로 등록하고, 나머지 주소는 **미정 기호**로 둔다. 이후 구간 경계에서는 추적값으로 상태나 메모리를 다시 초기화하지 않는다. P-code 창, 조건부 외부 호출 계약, 동결 native 요약이 동일한 전달 인터페이스를 사용한다. 가드 또는 읽기·쓰기·상태가 불일치하면 해당 노드에서 `unknown`이다. 이 적용기는 네이티브 trace의 경로와 비교하면서 실행하므로 독립적인 전체 입력 공간 실행기나 최종 공통 프로그램 IL은 아니다. 값 `X+5`는 여전히 별도 값 투영이다.

[적용 결과](bounded_python_program_application_result.json)에서 네 입력 모두 `bounded_path_applied`, 각각 6구간이다. 잘린 libc 명령, 추가 읽기·쓰기, 잘못된 반환 스택 접근, 마스크·요청 크기·반환 레지스터 변조, prefix→숫자 구간의 상태·메모리 변조, 미지원·누락 노드 **14건을 거부**했다. 미관측 메모리가 0으로 확정되지 않고 기호로 남는지도 별도로 확인했다. 이 부정 사례는 검증기의 오류 검출 예시이며 다른 경로의 정당성을 증명하지 않는다.

## 분기와 수명 판정

[후보 판정 결과](python_branch_candidate_audit_result.json)는 SMT의 두 SAT 후보를 실제 네이티브 경로와 구분한다. `X=0`의 앞부분 후보는 목표 PC 전에 133번째 명령에서 다른 길로 이탈하므로 목표 edge를 닫지 않는다. `X=251`의 숫자 구간 후보는 764번째 명령에서 실제 반대 successor를 실행했다. libc ASLR을 정규화한 후 목표 전까지 모든 native PC·바이트·successor를 비교하고, 목표 조건분기를 다시 디코딩해 명령 바이트와 두 합법 successor 중 정확히 반대 방향인지 확인했다. 이는 **제어 경로 재현**이며 source252의 모든 진입 메모리·레지스터가 동일했다는 뜻은 아니다. timeout·실행 오류 등은 판정 상태로 구별하지만 이번 두 사례에서 발생하지 않았다. 자동으로 모든 분기나 예외를 찾아내는 worklist는 아직 없다.

[기본 할당기 판정](python_default_allocator_authority_result.json)은 `252·254`의 객체 주소, 내부 helper 호출, 필드 쓰기와 이전 읽기를 다시 대조했다. 원시 `Write`의 증거는 있지만 객체 범위·세대·해제·재사용·소유권 계약은 없다. 따라서 두 경우 모두 `Allocate`는 `unknown`이다. 제한 풀 fixture의 인증서와 현재 바이너리·trace 메타데이터만 맞춘 가짜 인증서를 넣어도 승인하지 않는다. 기존 공통 수명 IL은 **확인된 소유권 계약이 있는 fixture**에만 사용할 수 있다.

## 다음 합격 조건

1. 이번 libc 경로 외의 크기·주소·구현을 별도 계약 또는 `unknown`으로 다루고, 사용되는 vector/mask live-out의 부재를 증명하거나 상태에 포함한다.
2. 분기·호출·예외 후보를 자동 worklist로 돌리고 목표 edge의 실제 실행 또는 `unsat`을 선행 경로와 환경 계약에 연결한다. 시간 초과와 선행 이탈은 닫힌 경로로 세지 않는다.
3. CPython 기본 allocator의 자원 범위, 세대, 이전 해제·재사용, 실패 반환, 소유권 이전을 네이티브 계약과 결합한 뒤에만 `Allocate`를 사용한다.
4. 공통 노드 적용기의 Python 전용 adapter를 Lua·JavaScript의 확인된 경로에도 적용하고, 반환값뿐 아니라 순서 있는 쓰기·제어·예외를 비교한다.

## 재현

```bash
cd experiments/interpreter-expression
../vm-transition-testbed/.venv/bin/python apply_bounded_python_program.py
../vm-transition-testbed/.venv/bin/python audit_python_branch_candidates.py
../vm-transition-testbed/.venv/bin/python audit_python_lifetime_authority.py
```
