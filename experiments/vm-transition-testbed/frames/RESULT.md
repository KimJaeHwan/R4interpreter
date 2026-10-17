# 지역 프레임, 간접 호출, 심볼 제거, 규모 실험

## 분리된 VM fixture

기존 CALL/RET 결과와 ELF는 그대로 두고 [`r4vm_frames.c`](../fixtures/r4vm_frames.c)를 별도로 만들었다. 이 VM은 호출마다 4개 지역 슬롯을 새로 만들고, 반환 시 선택된 슬롯 값 하나를 호출자의 목적 슬롯으로 옮긴다. `ICALL`은 VM 슬롯에 저장된 대상 PC를 읽는다. 64워드 프로그램, 최대 96 VM 단계, 깊이 4의 호출 스택을 가진다. 이 한도는 분석 대상 fixture의 실행 의미이기도 하다.

[`cases.json`](cases.json)의 네 프로그램은 분기 뒤 간접·중첩 호출, 지역 슬롯 격리, 호출 내부의 3회 루프, 범위를 벗어난 간접 호출을 포함한다. 독립 Python 오라클과 실제 C ELF는 **11/11** 입력에서 상태·출력·PC·쓰기 로그가 일치했다. [`analyze_frames.py`](../tools/analyze_frames.py)는 `execute(code,count,X)` 호출 ABI에서 angr 경로를 펼치고 **11/11** 결과와 fetch 순서를 맞혔다. 총 5개 완료 경로의 guard가 모든 64비트 `X`를 덮고 서로 겹치지 않음을 확인했다. `FMT001`의 두 식은 `X=0 → 10`, `X≠0 → X+5`; 호출 내 루프인 `FMT003`은 `X+21`이다. [경로 결과](angr-analysis.json)와 [채점](grade.json)을 보관했다.

새 fixture의 출력식은 **angr가 네이티브 명령을 기호 실행해 얻은 것**이다. 이 ELF에 대한 Ghidra P-code 재생이나 `daasdmlkas` backward slice는 아직 연결하지 않았다. [공통 관계 파일](../control-flow/common-logic.json)은 결과를 이전 R4VM·Lua 관계 옆에 담고 `analysis_strength: bounded_angr_native_path`로 출처를 구분한다.

## 심볼과 고정 주소 힌트 제거

같은 C 코드를 O2와 O1으로 각각 빌드해 `strip --strip-all`했다. [`probe_boundary_recovery.py`](../tools/probe_boundary_recovery.py)는 각 **심볼 제거 ELF만** CFG로 읽어, 여러 지점에서 동일한 로컬 함수로 호출하는 유일한 쌍을 `execute → output`으로 선택한다. 바이트코드 메모리의 각 워드 첫 바이트를 읽는 네이티브 지점에서 fetch를 기록한다. 함수 이름·진입 주소·fetch PC의 고정값은 분석기에 주지 않았다.

| 최적화 | 복구한 execute | 복구한 output | 관측 fetch 명령 | 결과·유효 fetch 일치 |
|---|---:|---:|---:|---:|
| O2 | `0x4013a0` | `0x4012f0` | `0x40140c` | 11/11 |
| O1 | `0x40126e` | `0x4011b6` | `0x401665` | 11/11 |

[복구 기록](boundary-recovery.json)에 빌드 해시와 사례별 시간·경로 수가 있다. 범위를 벗어난 PC는 실제 바이트코드 읽기가 없으므로 fetch 이벤트로 잡히지 않는다. 그 PC는 출력 ABI의 오류 인자에서 확인한다. 여전히 `execute`의 세 인자, `output`의 여섯 인자, 바이트코드의 `R4VM` 프레이밍, 고정 코드 버퍼 주소는 fixture 어댑터로 알고 있다. 반복 로컬 호출 규칙은 이 두 빌드에서 유일했으며, 임의의 인터프리터에서 자동으로 통한다는 주장은 아니다.

## 길이와 경로 증가

[`probe_scale.py`](../tools/probe_scale.py)는 동일 ELF에 더 긴 직선 프로그램과 서로 독립인 입력 비트 분기를 넣었다. 각 사례의 구체 입력 3개는 독립 오라클·네이티브 ELF와 대조했다. 분석 한도는 최대 6,000 네이티브 명령/경로, 동시 상태 64개, 전체 상태 128개, 사례당 45초다. 아래 시간은 이 실행의 측정값이며 머신에 따라 달라진다.

| 프로그램 | 완료 경로 | 최대 동시 상태 | 분석 시간 | 판정 |
|---|---:|---:|---:|---|
| 직선 5워드 | 1 | 1 | 0.9초 | proved |
| 직선 17워드 | 1 | 1 | 1.6초 | proved |
| 직선 49워드 | 1 | 1 | 3.6초 | proved |
| 직선 61워드 | 1 | 1 | 4.3초 | proved |
| 독립 비트 2·3·4·5·6개 | 4·8·16·32·64 | 3·6·11·21·41 | 1.4·2.2·4.0·7.8·15.0초 | proved |
| 독립 비트 7개 | 미완료 | 한도 초과 | 16.0초 | unknown |
| 독립 비트 5개, 동시 상태 한도 8 | 미완료 | 한도 초과 | 2.2초 | unknown |

`proved`는 위의 **고정 VM 실행 한도 및 분석 한도 안에서** 모든 기호 입력 경로의 출력 도달·guard 완전성·독립성을 확인했다는 뜻이다. `unknown`은 완성 경로 집합이 없으므로 입력 전체에 관한 결과를 낼 수 없다는 뜻이다. 해당 바이트코드의 구체 실행 오류를 뜻하지 않는다. [원자료](scale-results.json)에 각 사례의 상태·시간·이유를 저장했다.

## 재현과 남은 작업

Linux x86-64와 C 컴파일러, angr 환경에서 저장소 루트를 현재 디렉터리로 둔다.

```bash
python3 experiments/vm-transition-testbed/tools/build_frames_cases.py
/tmp/r4-angr-venv/bin/python experiments/vm-transition-testbed/tools/analyze_frames.py
/tmp/r4-angr-venv/bin/python experiments/vm-transition-testbed/tools/probe_boundary_recovery.py
/tmp/r4-angr-venv/bin/python experiments/vm-transition-testbed/tools/probe_scale.py
python3 experiments/vm-transition-testbed/tools/export_common_control_logic.py
```

`/tmp/r4-angr-venv/bin/python`은 이번 환경의 angr 가상환경 예시 경로다. 다른 환경에서는 `requirements-angr.txt`를 설치한 Python을 사용한다. `daasdmlkas` 체크아웃은 수정하지 않았다. 다음 분석 과제는 이 프레임 VM과 Lua 전체 호출 경로를 **경로별 P-code 상태·의존 그래프**로 재생해, angr의 경로 선택에 붙일 수 있는 정적 backward slice 축약을 증명하는 것이다.
