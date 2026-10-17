# 추적 스냅샷 없는 R4VM 시작 상태 실험

## 방법

[`angr_from_execute_abi.py`](../tools/angr_from_execute_abi.py)는 ELF의 `execute` 함수 호출 경계에서 상태를 만든다. 인자는 `.r4vm` 바이트를 놓은 버퍼 주소, 헤더의 명령 수, 64비트 기호 입력 `X`다. angr가 `execute`의 초기화 코드를 따라가고 첫 fetch `0x401410`에서 VM 코드 포인터·명령 수·PC 0·슬롯 0의 `X`를 확인한다. 이후 각 네이티브 분기를 따라 `output` 함수 진입 직전까지 탐색한다. 출력 함수의 인자와 쓰기 로그를 결과·PC·순서 있는 VM 슬롯 쓰기로 투영한다.

이 과정은 이전 ptrace 기록의 레지스터, 스택 바이트, VM 코드 버퍼 주소를 읽지 않는다. 매니페스트는 평가할 파일과 입력 목록을 제공할 뿐이며, 분석 함수는 ELF와 바이트코드만 사용한다. expected JSON과 fixture C 소스, opcode 표는 분석 함수에 들어가지 않는다. ELF를 네이티브로 실행하거나 새 ptrace 경로를 수집하지 않았다.

각 고정 바이트코드에 대해 모든 탐색 상태가 출력 경계에 도달해야 결과를 낸다. 도달한 경로의 guard가 64비트 `X` 전체를 덮고 서로 겹치지 않는지도 확인한다. 미해결 기호나 탐색 예산 초과가 있으면 `unknown`으로 남긴다.

## 결과

| 측정 | 결과 |
|---|---:|
R4VM 프로그램 | 12개 |
평가 입력 | 30개: 계산 28개, 런타임 오류 2개, unknown 0개 |
채점 | 30 pass, 0 fail; holdout 29 pass |
초기화 코드 → 첫 fetch | 프로그램마다 212개 네이티브 명령 |
출력까지 최대 탐색 깊이 | 697개 네이티브 명령 |
분기 사례 VMT007 | 출력 경로 2개; guard 합집합이 모든 64비트 `X`를 덮고 서로 겹치지 않음 |

정상 출력 28개의 결과값·PC·순서 있는 쓰기는 기존 스냅샷 방식과 모두 같다. VMT009 `type_error`, VMT011 `bad_opcode` 역시 오류 종류가 같으며, 이번 분석이 추가로 계산한 PC·쓰기 목록은 독립 expected JSON과 일치한다. **30개 모두 PC·순서 있는 쓰기가 독립 정답과 일치**했다. VMT010의 내부 `opaque_add` 호출도 hook 없이 따라가 입력 `9 → 12`, `0 → 3`을 얻었다.

[분석 JSON](ANGR_EXECUTE_ABI_ANALYSIS.json)에는 각 프로그램의 탐색 깊이와 샘플별 결과를, [채점 JSON](ANGR_EXECUTE_ABI_GRADE.json)에는 판정을 보관했다. 채점 전체 39개 중 Lua 9개는 `not_run`이다. 이번 실험은 R4VM 시작 상태에 한정되며 Lua 결과를 새로 얻지 않았다.

## 현재 경계

`execute`와 `output`의 함수 심볼, 첫 fetch 주소, System V 호출 인자, 출력 인자와 쓰기 로그 배치는 이 ELF에 맞춘 수동 힌트다. 입력 버퍼 주소 `0x50000000`은 angr 내부의 합성 주소다. ELF가 바뀌거나 심볼이 제거되면 경계와 배치를 다시 찾아야 한다. 따라서 이 결과는 임의의 인터프리터나 VMP에 대한 자동 분석을 뜻하지 않는다. 경로가 늘어나는 프로그램은 현재 1,200명령·64개 동시 상태 제한에 걸릴 수 있다.

다음에는 이 호출 상태에서 얻은 첫 fetch 상태를 P-code 경로 요약에 연결하고, fetch→fetch 전이를 합성해야 한다. 그 과정에서 저장된 스택 스냅샷과 실행 추적 경로에 대한 의존이 실제로 사라지는지 따로 측정해야 한다.

## 재현

Linux x86-64의 R4interpreter 저장소 루트에서 실행한다. `build/r4vm`이 없다면 먼저 보관된 ELF를 복원한다. `requirements-angr.txt`에는 angr와 필요한 버전의 `bitstring`을 지정했다.

```bash
python3 experiments/vm-transition-testbed/tools/restore_frozen_binary.py
python3 -m venv experiments/vm-transition-testbed/.venv-angr
experiments/vm-transition-testbed/.venv-angr/bin/python -m pip install -r experiments/vm-transition-testbed/requirements-angr.txt
experiments/vm-transition-testbed/.venv-angr/bin/python experiments/vm-transition-testbed/tools/angr_from_execute_abi.py --output experiments/vm-transition-testbed/reports/angr-from-execute-abi.json
experiments/vm-transition-testbed/.venv-angr/bin/python experiments/vm-transition-testbed/tools/compare_analysis.py experiments/vm-transition-testbed/reports/angr-from-execute-abi.json
```

마지막 채점은 Lua 9개가 미실행이므로 `pass: 30`, `not_run: 9`로 출력된다. 보관된 ELF의 SHA-256은 `de3a9064af955bd59b342b9fff0273efded539bb22e68e460c27328df7b09f0a`다.
