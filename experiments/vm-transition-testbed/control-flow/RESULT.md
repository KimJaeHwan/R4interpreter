# 분기와 VM 함수 호출 실험

## 범위

기존 R4VM ELF와 동결 P-code 요약을 보존하기 위해 별도 [`r4vm_control.c`](../fixtures/r4vm_control.c)를 사용했다. 새 VM은 바이트코드 `CALL`, `RET`, 절대 `JUMP`와 깊이 4의 반환 주소 스택을 가진다. VM 함수는 별도의 지역 변수 프레임 없이 기존 슬롯 4개를 공유한다. 따라서 이 실험은 **호출 제어 흐름과 반환 스택**을 확인하지만 일반적인 지역 변수·재귀 프레임까지 다루지는 않는다.

| 사례 | 구조 | 기대 출력식 |
|---|---|---|
| CFT001 | `X=0` 분기 뒤 두 단계 중첩 호출, 복귀 후 합류 | `X=0 → 10`, `X≠0 → X+5` |
| CFT002 | 같은 함수를 서로 다른 인자로 두 번 호출 | `X+14` |
| CFT003 | 호출을 포함한 3회 루프 | `X+21` |
| CFT004 | 호출 없이 반환 | `call_underflow` |
| CFT005 | 반환 없이 반복 호출 | `call_overflow` |

## 실제 측정

[`cases.json`](cases.json)에서 5개 프로그램·12개 평가 입력을 만들었다. 독립 Python 오라클과 C ELF 실행 결과는 **12/12** 같았다. `execute` 호출 ABI에서 만든 angr 상태는 이전 추적의 스택·레지스터 스냅샷 없이 모든 입력의 결과값, 오류, PC, 순서 있는 쓰기와 **VM fetch PC 방문 순서**를 맞혔다. CFT001은 `X=0`과 `X≠0` 두 출력 경로를 만들었으며, 전체 6개 경로가 출력에 도달했다. 각 프로그램에서 완성 경로의 guard가 모든 64비트 `X`를 덮고 서로 겹치지 않는지도 확인했다.

새 [Ghidra Bundle](r4vm_control_bundle.tar.gz)의 Low P-code를 angr가 선택한 각 경로에서 재생했다. 6개 경로를 52개 fetch 구간으로 나누어 공통 [`project_path`](../../interpreter-expression/logic_projection.py) 투영기에 연결했다. 구간별 다음 VM PC와 네이티브 명령 순서가 angr와 같았고, 경로 guard·출력 함수 인자 6개·쓰기 로그 필드가 Z3에서 angr 식과 동치였다. P-code가 합성한 출력식은 위 표와 같고, 독립 샘플 채점은 **12/12**였다. [angr 결과](angr-analysis.json), [P-code 전이 결과](pcode-projection.json), [채점 결과](grade.json), [P-code 식 채점](pcode-grade.json)에 근거를 보관했다.

이 결과는 **angr가 경로를 찾고, P-code가 각 경로의 효과를 재생·합성한 것**이다. P-code만으로 전체 CFG의 경로를 자동 발견한 것은 아니다. 입력당 한 구체 witness로 P-code 경로를 선택하지만 출력식과 guard는 64비트 기호 `X`로 남겨 angr 경로식과 비교했다. 실행 한도는 2,500 네이티브 명령·64개 동시 상태이며, 임의 크기 VM의 경로 폭발을 해결한 것은 아니다.

## backward slice와 공통 형식

같은 Bundle을 읽기 전용 `daasdmlkas` 전체 함수 SSA에 넣고 결과 슬롯의 `STORE`를 역방향 slice했다. 그래프는 2,849노드·5,857간선이다. 값 쓰기 경로 네 개의 data-only slice는 동일한 200개 연산을 포함했고, 그중 **73~93개가 해당 실행 경로 밖**이었다. 미해결 읽기는 경로마다 29개, 함수 전체 미해결 쓰기는 11개였다. [slice 측정](static-slice.json)은 기존 전체 함수 slice만으로 호출·루프 전이를 확정할 수 없음을 보여준다. 이번 축약은 경로별 P-code 상태 버전과 Z3 식 단순화에서 나온 것이며, `daasdmlkas` backward slice를 경로별 엔진에 통합했다고 주장하지 않는다.

[공통 guarded relation 형식](common-logic.json)에 새 R4VM 프로그램 5개와 **보관된** Lua 핸들러·두 핸들러 연결 3개를 담았다. R4VM 경로는 출력까지 분석했고 guard 완전성을 확인했다. Lua의 `X+7`, `X+11`, `X+18`은 기존 결과를 같은 형식으로 옮긴 것으로, 함수 반환까지의 분석도 아니고 guard 완전성도 증명되지 않아 `guard_proven: false`로 표시했다. 따라서 형식 공유는 확인했지만 두 엔진의 추출 절차가 통합되었다는 의미는 아니다.

## 재현

Linux x86-64에서 저장소 루트를 기준으로 아래 명령을 실행한다. `.venv-angr`에는 [`requirements-angr.txt`](../requirements-angr.txt)를 설치한다. 고정 ELF는 Bundle에서 해시 검증 후 복원하므로 컴파일러 차이에 따른 주소 변화를 피한다.

```bash
cd experiments/vm-transition-testbed
python3 tools/build_control_cases.py --check
python3 tools/restore_control_binary.py
python3 tools/run_control_fixtures.py
.venv-angr/bin/python tools/angr_from_execute_abi.py --control-flow --output control-flow/angr-analysis.json
.venv-angr/bin/python tools/grade_control_cases.py control-flow/angr-analysis.json
.venv-angr/bin/python tools/project_control_pcode.py
.venv-angr/bin/python tools/grade_control_projection.py
python3 tools/export_common_control_logic.py
```

`probe_control_slice.py`는 선택 사항이다. 실행에는 읽기 전용 `daasdmlkas` 체크아웃과 그 Python 의존성이 추가로 필요하다. 이 실험에서 `daasdmlkas` 파일은 수정하지 않았다. Ghidra로 새 Bundle을 재생성할 필요 없이 보관본으로 핵심 결과를 재현할 수 있다.

## 다음 과제

1. 경로별 P-code 작업에서 `daasdmlkas` 의존 그래프를 반복별로 분리해 실제 backward slice로 불필요한 연산 수를 계측한다.
2. 지역 변수 프레임·동적 호출 대상·재귀의 종료 조건을 추가해 현재의 공유 슬롯·고정 깊이 가정을 깨본다.
3. Lua의 분기와 함수 호출을 새로 추출해 같은 guard·상태 효과·반환 형식으로 계산하고 `guard_proven` 범위를 넓힌다.
