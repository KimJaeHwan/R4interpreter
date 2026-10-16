# R4VM 한 ADD 명령의 P-code 경로 생성

## 목표와 경계

R4VM의 fetch 지점 `0x401410`부터 다음 fetch까지, 네이티브 ELF 실행이나 보관된 native path 조회 없이 Ghidra Bundle의 Low P-code를 해석해 ADD 전이를 만든다. [생성기](../tools/static_pcode_step.py)는 주어진 바이트코드·입력의 **구체값으로 분기를 선택**하는 동시에 레지스터·메모리·조건을 기호식으로 유지한다. 따라서 이것은 입력별 경로 생성과 그 경로의 기호 요약이며, 전체 CFG의 모든 경로 열거는 아니다.

초기 레지스터·스택·코드 버퍼 위치는 이전 ptrace 훈련에서 보관한 `baseline`이다. ELF의 로드 영역은 바이너리에서 읽고, 접근할 수 없는 메모리를 만나면 실패한다. 이번 단계는 **새 추적 없이 경로를 찾는 것**에는 성공했지만, 실행 추적에서 얻은 초기 상태에도 아직 의존한다.

## 과정

1. Bundle 명령의 P-code를 주소 순서가 아닌 CFG successor에 따라 실행한다. 조건 분기에는 현재 구체값을 사용하고 해당 조건의 기호 guard를 남긴다.
2. P-code `LOAD/STORE`와 레지스터 연산을 구체값·기호식으로 함께 갱신한다. 순서 있는 메모리 쓰기와 종료 레지스터 식을 기존 공통 전이 포맷으로 저장한다.
3. 다음 fetch에 닿으면 멈춘다. 보관된 추적 경로는 [평가기](../tools/evaluate_static_add.py)가 **후에 비교할 때만** 읽는다.
4. 기존 공통 식 투영기로 바이트코드별 입력식과 다음 VM PC를 계산한다.

## 결과

| 바이트코드 / 경로 선택 입력 | 정적 생성 경로 | 기호식 축약 | 다음 VM PC | 보관 요약과 비교 |
|---|---|---|---:|---|
| VMT001 / 5 | 52 native, 375 P-code | `X + 7` | 1 | 모든 비교 필드 일치 |
| VMT001 / 9 | 52 native, 375 P-code | `X + 7` | 1 | 모든 비교 필드 일치 |
| VMT002 / 9 | 52 native, 375 P-code | `X + 11` | 1 | 모든 비교 필드 일치 |
| VMT002 / 0 | 52 native, 375 P-code | `X + 11` | 1 | 모든 비교 필드 일치 |

네 경우 모두 같은 native path ID `347cd71f1ec34c41`을 얻었고, path guard 13개, P-code 읽기 8개, 순서 있는 쓰기 5개가 생성됐다. 보관 요약과 비교한 `native_path`, `guards`, `reads`, `effects`, 종료 `registers`·`flags` 문자열이 모두 같다. 입력식 `X + 7`과 `X + 11`은 공통 투영기의 64비트 bitvector 동치 확인을 통과했다. 이 바이트코드와 초기 상태에서 투영된 비자명한 `X` guard는 0개다. [후보 전이 JSON](STATIC_ADD_STEP.json)과 [4사례 평가 JSON](STATIC_ADD_EVALUATION.json)에 값이 있다.

## backward slice의 역할과 남은 일

이번 경로 생성기는 이전 정적 slice 실험에서 발견한 함수 전체 의존 그래프를 그대로 실행하지 않는다. 전체 그래프는 루프 반복과 다른 opcode 경로를 합쳐 앞선 쓰기에 뒤쪽 ADD까지 연결했다. 대신 P-code를 **한 fetch 구간의 선택된 경로에 따라** 실행하고 기호식을 만든다. 앞으로 backward slice는 이 경로별 전이에서 실제 관찰값에 필요한 연산을 줄이고, 미해결 메모리·호출 의존을 찾아 `unknown`으로 판정하는 데 붙이는 편이 맞다.

이 결과는 ADD 한 경로와 보관된 초기 cutpoint에서의 결과다. 모든 바이트코드/경로의 guard 완전성, 별칭·frame 보존, 호출 효과, 루프 종료를 증명하지 않았다. 다음 구현은 (1) trace `baseline` 대신 ELF 초기화 또는 명시된 진입 ABI에서 cutpoint 상태를 만들고, (2) 입력 하나로 분기를 고르지 않고 CFG 분기를 기호적으로 나눠 경로별 메모리 버전을 유지하며, (3) 그 경로에서 backward slice와 alias 검사를 적용하는 것이다. 그 뒤 ADD 외 R4VM 경로와 Lua를 같은 절차로 다룰 수 있다.

## 재현

R4interpreter 루트에서 `requirements-analysis.txt` 의존성을 설치하고 `tools/restore_frozen_binary.py`로 해시가 맞는 ELF를 복원한 뒤:

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/vm-transition-testbed/tools/static_pcode_step.py --output experiments/vm-transition-testbed/reports/static-add-step.json
experiments/vm-transition-testbed/.venv/bin/python experiments/vm-transition-testbed/tools/evaluate_static_add.py --output experiments/vm-transition-testbed/reports/static-add-evaluation.json
```

두 명령은 ELF를 실행하거나 ptrace를 호출하지 않는다.
