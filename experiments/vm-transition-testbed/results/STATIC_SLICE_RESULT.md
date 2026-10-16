# 정적 SSA 역방향 slice 실험

## 질문과 방법

`daasdmlkas`의 읽기 전용 정규화·slice API에 보관된 R4VM 및 Lua Ghidra Bundle을 넣어, 실행 추적 없이 VM의 결과 쓰기와 분기에서 필요한 P-code를 찾을 수 있는지 확인했다. `daasdmlkas` 저장소는 수정하지 않았다. 비교 지점은 이전 실행 추적에서 찾은 R4VM ADD·분기·HALT 경로와 Lua ADD 핸들러의 쓰기·분기 주소를 사용했다. 따라서 **root 선택까지 완전 자동인 실험은 아니다.** 정규화와 slice 질의는 보관 경로를 입력받지 않으며 ELF를 실행하지 않는다. 결과 원본은 [STATIC_SLICE_PROBE.json](STATIC_SLICE_PROBE.json)에 있다.

## 관찰

| 대상과 root | 함수 전체 P-code | 데이터 slice | 제어 의존 포함 slice | 미해결 읽기 / 함수 전체 미해결 쓰기 |
|---|---:|---:|---:|---:|
| R4VM ADD 경로의 쓰기 5개 + 다음 fetch 분기 | 1,115 | 175 | 308 | 38 / 10 (제어 의존 포함) |
| R4VM 분기 경로의 다음 fetch 분기 | 1,115 | 6 | 308 | 38 / 10 (제어 의존 포함) |
| R4VM HALT의 마지막 반환값 설정 | 1,115 | 1 | 325 | 40 / 10 (제어 의존 포함) |
| Lua ADD 핸들러의 첫 쓰기 `0x417cea` | 26,892 | 4,910 | 7,322 | 1,659 / 201 (제어 의존 포함) |
| Lua ADD 핸들러의 다음 쓰기 `0x417ced` | 26,892 | 4,910 | 7,322 | 1,659 / 201 (제어 의존 포함) |

R4VM ADD의 두 저장 root에서 실제 덧셈 P-code `0x40160e:2:INT_ADD`까지 도달했다. 정적 그래프가 관련 연산을 잃지는 않았다. 그러나 ADD의 제어 의존 포함 slice 308개 중 168개는 보관된 실제 실행 경로 밖에 있다. `175/308`과 같은 숫자는 연산 후보의 크기이지 원본 스크립트로 축약된 크기가 아니다. 실행 경로의 모든 P-code가 결과에 필요한 것도 아니므로, 경로와의 교집합을 정밀도나 정확도로 해석하지 않는다.

Lua에서는 더 강한 반례가 있다. 주소상 앞선 쓰기 `0x417cea:1:STORE`의 정적 slice에도 뒤의 `0x417ced:0:INT_ADD`가 포함된다. 루프·메모리 JOIN을 포함한 함수 전체 의존성이므로, slice에 들어왔다는 사실만으로 그 덧셈이 해당 쓰기의 원인이라고 말할 수 없다. R4VM의 서로 다른 STORE root도 동일한 큰 slice로 합쳐졌다.

## 판정

**공통 P-code/SSA 진입점은 작동하지만, 현재 함수 단위 slice만으로는 조건·순서 있는 쓰기·다음 PC를 정확히 추출하지 못한다.** 특히 미해결 메모리 의존성과 함수 전체 CFG의 경로 합류가 남는다. 이번 실행에서 새 정적 전이식이나 추가 통과 사례를 만들지 않았으며, 기존 28/30 R4VM 평가 결과는 추적 기반 조건부 요약의 결과다. 보관된 경로를 root 선택·교집합 평가에 썼으므로 ptrace 없이 handler root를 발견하는 문제도 미해결이다.

## 다음 구현 단위

1. fetch에서 다음 fetch/출력까지의 CFG를 경계로 나누고, 모든 STORE를 결과로 취급하지 않도록 관찰할 VM 상태·출력 root를 정한다. 수동 주소 힌트를 허용하면 그 사실을 결과에 기록한다.
2. 경계 안의 분기마다 path guard와 경로별 메모리 버전을 만든다. 함수 전체 JOIN이 이전·다음 루프 반복과 다른 opcode 경로를 한 식에 섞지 않도록 한다.
3. 경로별 후보를 기존 공통 전이 포맷의 guard, ordered effects, next PC로 투영한다. 별칭·호출 의존성을 풀지 못하면 `unknown`으로 두고, 보관된 11개 경로 및 별도 입력 30개와 대조한다.
4. R4VM에서 경로 선택에 기존 추적을 쓰지 않고 동등한 결과를 얻은 뒤 동일한 경계·guard·메모리 처리를 Lua ADD에 적용한다.

## 재현

Python 3.11 이상에서 R4interpreter와 `daasdmlkas`를 형제 디렉터리에 둔다. 후자는 기준 커밋 `3a274f93d455d3caaebf72365e64820770341787`의 **읽기 전용 의존성**이다. 다른 위치이면 `DAASDMLKAS_REPO`로 지정한다. R4interpreter 루트에서:

```bash
python3 -m venv experiments/vm-transition-testbed/.venv
experiments/vm-transition-testbed/.venv/bin/python -m pip install -r experiments/vm-transition-testbed/requirements-static-slice.txt
experiments/vm-transition-testbed/.venv/bin/python experiments/vm-transition-testbed/tools/probe_static_slice.py --output experiments/vm-transition-testbed/reports/static-slice-probe.json
```

스크립트는 Bundle을 임시 개인 디렉터리에 풀고 `daasdmlkas` API로 읽는다. ELF 실행, ptrace, Ghidra 재실행은 필요하지 않다. 결과는 지정한 JSON 경로에만 쓴다.
