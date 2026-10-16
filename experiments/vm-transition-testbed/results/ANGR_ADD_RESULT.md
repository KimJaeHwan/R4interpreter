# angr와 P-code의 ADD 한 명령 비교

## 실험

R4VM의 네이티브 fetch 지점 `0x401410`에서 입력 `X`를 64비트 기호값으로 놓고 angr가 네이티브 ELF를 VEX로 실행했다. 다음 fetch 또는 출력 지점에서 멈추며, 같은 시작 상태의 [Ghidra Bundle P-code 경로 생성기](../tools/static_pcode_step.py)와 경로·조건·상태 쓰기·다음 PC를 비교했다. angr와 P-code는 서로의 경로를 선택에 사용하지 않는다. 두 쪽의 식은 공통 입력 기호로 Z3에 넣고 `서로 다름`이 불가능한지 확인했다.

초기 레지스터, 스택 바이트 및 바이트코드 버퍼 주소는 이전 ptrace 실험에서 얻은 cutpoint `baseline`을 사용했다. 이 실험 중 ELF를 네이티브로 실행하거나 ptrace를 호출하지 않았다. 바이트코드는 각각 `VMT001`의 즉시값 7과 `VMT002`의 즉시값 11로 고정했다.

| 바이트코드 | angr 완료 경로 | 네이티브 경로 | 입력 관련 경로 제약 | 상태 쓰기 값 | 슬롯 0 / 다음 VM PC |
|---|---:|---:|---:|---|---|
| VMT001 | 1개 | P-code와 같은 52개 명령 | 0개 | 5개 모두 P-code와 64비트 동치 | `X + 7` / `1` 동치 |
| VMT002 | 1개 | P-code와 같은 52개 명령 | 0개 | 5개 모두 P-code와 64비트 동치 | `X + 11` / `1` 동치 |

이 시작 상태에서 ADD의 분기는 `X` 값으로 갈라지지 않았다. P-code 투영의 비자명한 입력 guard도 0개다. 이 결과는 해당 두 바이트코드의 **한 명령**에 관한 것이며, 다른 초기 상태나 opcode의 경로 완전성을 뜻하지 않는다. [수치·동치 판정 원본](ANGR_ADD_PROBE.json)에 각 쓰기 주소와 폭이 있다.

## VEX 임시 쓰기

angr의 원시 메모리 쓰기 이벤트는 6개였고 Ghidra P-code 효과는 5개였다. 추가 1개는 주소 `0x401573`의 레지스터 전용 `bt r12, rax`에서 나왔다. VEX 리프터가 `r12`를 `rsp - 0x120`에 잠시 써서 비트를 읽고 `rsp`를 복원한다. 같은 네이티브 명령의 Ghidra P-code에는 `STORE`가 없으며, VM 슬롯·쓰기 기록 주소와도 다르다. 평가기는 이 **특정 명령·주소·폭**을 별도 이벤트로 보고했다. 임의의 추가 쓰기를 일반적으로 무시하는 규칙은 만들지 않았다.

이 차이는 두 IR의 쓰기 이벤트를 그대로 한 줄씩 대응시키면 오류가 생긴다는 사례다. 의미 있는 VM 상태 변화의 비교에는 관찰 root와 네이티브 명령의 실제 의미가 필요하다.

## backward slice와의 연결 및 남은 단계

이번 코드는 angr가 가능한 경로를 찾고, 기존 P-code 전이 생성기와 그 결과를 검증하는 **첫 결합**이다. `daasdmlkas`의 SSA 그래프를 angr 실행 상태에 직접 결합하거나, slice로 P-code 실행 범위를 자동 축소하지는 않았다. 앞선 [정적 slice 실험](STATIC_SLICE_RESULT.md)에서 함수 전체 slice가 다른 경로·루프 반복을 섞는 것을 확인했기 때문이다.

다음 구현은 angr가 확인한 fetch→fetch 경로를 기준으로 P-code의 경로별 메모리 버전과 의존성을 만들고, 그 안에서 backward slice를 적용하는 것이다. 특히 alias, 호출, VEX와 P-code의 임시 연산 차이를 해소하지 못하면 `unknown`이어야 한다. 이후 분기 opcode로 여러 angr 상태가 실제로 생기는 경우를 시험하고, 추적 기반 초기 `baseline`을 ELF 초기화 경로 또는 명시된 진입 ABI로 대체해야 한다.

## 재현

기존 분석 가상환경은 Z3 4.16을 사용하고 angr 9.2.223은 Z3 4.13을 요구하므로 별도 가상환경을 사용한다. angr의 현재 의존성에서 `bitstring` 5는 VEX import 오류가 발생하여 4.x로 고정했다. R4interpreter 루트에서:

```bash
python3 -m venv experiments/vm-transition-testbed/.venv-angr
experiments/vm-transition-testbed/.venv-angr/bin/python -m pip install -r experiments/vm-transition-testbed/requirements-angr.txt
python3 experiments/vm-transition-testbed/tools/restore_frozen_binary.py
experiments/vm-transition-testbed/.venv-angr/bin/python experiments/vm-transition-testbed/tools/probe_angr_add.py --output experiments/vm-transition-testbed/reports/angr-add-probe.json
```

Unicorn 가속 라이브러리가 없는 환경에서는 angr가 선택 기능의 로드 오류를 출력할 수 있다. 이 실험은 Unicorn을 사용하지 않는다.
