# angr 보완 경로: 분기와 미지원 호출

## 무엇을 바꿨나

기존 P-code 경로 분석기가 `unknown`으로 남긴 R4VM 입력에만 [angr 보완기](../tools/angr_fallback_r4vm.py)를 적용했다. 입력 `X`를 64비트 기호값으로 두고 ELF의 네이티브 명령을 `0x401410`부터 실제 `output` 함수 진입 전까지 탐색한다. 분기가 갈라지면 각 상태의 조건을 유지한다. 모든 탐색 상태가 출력에 도달하고, 평가 입력을 받아들이는 상태가 정확히 하나이며, 출력 인자·순서 있는 쓰기가 모두 유일하게 결정될 때만 `computed`를 반환한다. 경로/상태 예산이나 미해결 기호가 남으면 기존 `unknown`을 유지한다.

ELF를 네이티브로 실행하거나 ptrace로 새 경로를 뽑지 않았다. 시작 레지스터·스택·코드 버퍼 주소는 여전히 이전 추적의 cutpoint `baseline`이다. 미지원 `opaque_add`는 의미를 사전에 입력하거나 hook으로 대체하지 않고, angr가 ELF 안의 helper 명령을 따라갔다.

## 측정 결과

| 범위 | 기존 P-code 요약 | angr 보완 후 | 이번 증가 |
|---|---:|---:|---:|
| R4VM 30개 평가 입력 | 28 pass, 2 accepted unknown | **30 pass** | VMT010 2개 계산 |
| 보관된 Lua 9개를 합친 39개 입력 | 37 pass, 2 accepted unknown | **39 pass** | 같은 VMT010 2개 |

VMT010의 두 입력에서 angr는 helper를 포함해 네이티브 83개 명령을 탐색했고, 완료 상태 1개와 비자명한 입력 경로 조건 0개를 얻었다. 출력식 `X + 3`을 기호적으로 확인했다. 입력 `9`는 결과 `12`, 입력 `0`은 결과 `3`; 둘 다 다음 VM PC `2`, 쓰기 `[{slot: 1, value: 결과, tag: 3}]`이다. 기존 분석기는 이 두 입력에서 일치하는 P-code 요약 경로가 없어 `unknown`을 냈다.

분기 사례 VMT007도 별도로 조사했다. angr는 `X=0` 경로와 `X≠0` 경로 두 개를 만들었고, 두 조건의 **합집합이 모든 64비트 X를 덮고 서로 겹치지 않음**을 확인했다. 각 결과는 `42`와 `X + 7`이다. VMT007은 기존 분석기도 이미 계산하던 사례이므로 통과 수 증가에는 포함하지 않았다.

[보완 분석 JSON](ANGR_FALLBACK_ANALYSIS.json), [R4VM 기존 채점](ANGR_FALLBACK_BASELINE_GRADE.json), [R4VM 보완 채점](ANGR_FALLBACK_GRADE.json), [Lua 포함 채점](ANGR_FALLBACK_COMBINED_GRADE.json)에 입력별 근거가 있다. Lua 9개는 이번 angr 실행 결과가 아니라 이전에 검증해 보관한 예측이다.

## 정확성의 범위와 다음 단계

이는 **정해진 평가 입력의 채점 결과**와 cutpoint 상태를 전제로 한 VMT010/VMT007의 기호 경로 결과다. 모든 바이트코드, 모든 VM 초기 상태, 호출·메모리 별칭의 일반적 보존을 증명하지는 않았다. 현재 `unknown` 감소는 angr가 helper 내부를 직접 실행했기 때문이며, `daasdmlkas` backward slice를 angr 상태와 결합한 성과로 계산하지 않는다.

다음에는 angr가 찾은 각 fetch→fetch 경로에 P-code 의존성 그래프를 별도로 만들어 backward slice를 적용해야 한다. 함수 전체 SSA 그래프는 다른 경로와 루프 반복을 섞으므로 그대로 교차하면 안 된다. 또한 시작 `baseline`을 추적 없이 얻을 방법과, VEX 임시 메모리 연산 및 실제 VM 상태 쓰기를 구분할 공통 경계를 마련해야 한다.

## 재현

R4interpreter 루트에서 해시가 맞는 ELF를 복원하고 기존 P-code 분석을 먼저 실행한다. angr는 별도 가상환경과 [`requirements-angr.txt`](../requirements-angr.txt)를 사용한다.

```bash
python3 experiments/vm-transition-testbed/tools/restore_frozen_binary.py
experiments/vm-transition-testbed/.venv/bin/python experiments/vm-transition-testbed/tools/run_r4vm_analysis.py --output experiments/vm-transition-testbed/reports/current-r4vm-analysis.json
experiments/vm-transition-testbed/.venv-angr/bin/python experiments/vm-transition-testbed/tools/angr_fallback_r4vm.py --baseline experiments/vm-transition-testbed/reports/current-r4vm-analysis.json --output experiments/vm-transition-testbed/reports/angr-fallback-r4vm.json
experiments/vm-transition-testbed/.venv/bin/python experiments/vm-transition-testbed/tools/compare_analysis.py experiments/vm-transition-testbed/reports/angr-fallback-r4vm.json
```

`.venv`와 `.venv-angr` 생성·의존성 설치 방법은 [테스트베드 README](../README.md)와 [angr ADD 비교](ANGR_ADD_RESULT.md)에 있다. 결과 JSON의 `branch_probe`는 채점용 예측과 분리된 기호 분기 관찰이다.
