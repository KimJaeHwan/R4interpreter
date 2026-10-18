# 세 인터프리터의 관측 구간 상태 전이 실험

이 문서는 첫 공통 전이 실험의 기준 결과(9건 중 8건)를 기록한다. Python 할당·JavaScript 문자열 경로를 추가한 최신 결과(14건 중 12건)는 [후속 실험](EXPANDED_PATH_VALUE_PROJECTION_RESULT.md)을 참조한다.

## 목표와 경계

기존 결과는 Lua의 전이 요약, JavaScript `AddSmi`의 11개 명령 앞부분, Python `BINARY_OP`의 숫자 결과를 따로 다뤘다. 이번에는 **한 네이티브 처리 구간의 진입부터 다음 핸들러 또는 fetch 경계까지**를 조건부 상태 전이로 저장했다. 대상은 고정된 Lua 실행 파일, CPython 3.13.5, Node 24.19.0 `--jitless` 실행이다. 원본 스크립트나 opcode 의미표는 요약 생성 입력으로 사용하지 않았다. 별도 프로그램의 출력은 차등 검증에 사용했다.

| 엔진과 구간 | 소스 P-code | 저장한 상태와 효과 | 새 실행에 적용 |
|---|---:|---|---|
| Lua `+7` 관측 핸들러 | 기존 요약의 265개 | 16 GPR·5 플래그, 파생 코드 포인터, 고유 읽기 2개, 쓰기 2개, 다음 fetch | `+11` 입력 9, `+7` 입력 0: 2/2 |
| Python cached PyLong `BINARY_OP` | 626개, 네이티브 116개 | 16 GPR·5 플래그, 읽기 31개, 순서 있는 쓰기 12개, 다음 핸들러 | 입력 37·251: 2/2 |
| JavaScript `AddSmi` 두 관측 구간 | 각각 142·122개, 네이티브 26·23개 | 16 GPR·5 플래그, VM 커서, 읽기 9·8개, 쓰기 1·0개, 다음 핸들러 | `twoAdds` 두 위치와 별도 `wrappedAdd` 37·251: 4/4; 252는 `unknown` |

Python의 기존 값 요약에서 제외했던 네이티브 쓰기 11개를 포함해 **총 12개 쓰기**의 순서·주소·값을 식으로 저장했다. 여기에는 프레임과 네이티브 스택의 쓰기도 들어간다. JavaScript에서는 앞부분 뒤의 분배까지 저장하고, 첫 `AddSmi`와 결합된 `Star0`의 슬롯 쓰기도 포함했다. 대상 실행의 P-code를 다시 재생하지 않고 저장된 식만 평가했다. 세 요약의 독립 적용 결과는 [JavaScript 보고서](js_full_handler_reuse_result.json), [Python 보고서](python_full_handler_reuse_result.json)에 있다.

## 공통 형식과 적용기

[`common_three_engine_transitions.json`](common_three_engine_transitions.json)은 Lua 1개, Python 1개, JavaScript 2개의 조건부 사례를 `common-observed-transition-v1`로 저장한다. 각 사례에는 다음 요소가 있다.

```text
identity: 바이너리 해시, 진입·종료 PC, 관측 경로의 명령 형태
interface: 타입과 진입 바인딩을 가진 레지스터·플래그·초기 메모리
condition: 해당 P-code 경로가 실행되는 조건식
outputs: 16 GPR와 5개 모델링한 플래그의 식
derived_outputs: VM 커서 또는 코드 포인터의 식
reads: 읽기 주소와 폭
effects: 순서 있는 Write 주소·폭·값
successor: 다음 네이티브 경계의 주소식
preconditions: 엔진별 입력 계약과 검증할 외부 상태
```

[`common_observed_transition.py`](common_observed_transition.py)는 세 엔진 모두에 같은 **타입 있는 SMT 식 평가, guard 판정, 출력 상태·읽기·쓰기·다음 경계 대조**를 적용한다. 입력 바인딩과 전제 확인은 엔진별 adapter가 맡는다. Lua는 진입 메모리 snapshot의 바이트를 `M0`에 바인딩한다. Python은 실제 피연산자 슬롯의 PyLong 포인터·값, 고정 캐시 이미지와 결과 슬롯, 캐시 쓰기 부재를 확인한다. JavaScript는 저장된 Smi 조건과 두 경로의 명령 형태를 확인한다. 적용기는 16 GPR·5 플래그의 완전한 선언을 요구하고 지원하지 않는 효과 종류·스키마·엔진은 `unknown`으로 돌린다.

[공통 적용 결과](common_three_engine_application_result.json)는 9개 대상 중 8개에서 전체 **관측 구간**의 상태와 효과가 일치하고, JavaScript 입력 252는 `unknown`이라고 기록한다. 대상 P-code 재생은 0회다. 잘못된 스키마·엔진·출력 및 파생 출력 누락·효과 종류·Lua snapshot·Python 피연산자·JavaScript 쓰기·후속 경계를 바꾼 10개 부정 입력도 모두 `unknown`이다. 이는 공통 **평가 메커니즘**이 세 대상에 통했다는 결과이며, 세 엔진의 모든 opcode와 경로를 자동으로 발견했다는 결과는 아니다.

## 대체 경로에서의 거부

[대체 경로 보고서](alternate_path_rejection_result.json)는 네 가지를 별도로 측정했다.

| 사례 | 관측 | 현재 요약의 결과 |
|---|---|---|
| Python 입력 252 | 입력 객체는 캐시에 있지만 결과 257은 캐시 밖이다. 116개 명령 경로가 인덱스 81(82번째 명령)에서 갈라져 146개를 거친다. | `unknown` |
| JavaScript 숫자 252 | 23개 명령 경로는 같으나 증명한 숫자 범위 밖이다. | `unknown` |
| JavaScript 문자열 `"37"` | `"375"` 출력. 숫자 경로와 인덱스 7(8번째 명령)에서 분기한다. | `unknown` |
| JavaScript BigInt `37n` | Number 5와 섞여 `TypeError`. 숫자 경로와 인덱스 7(8번째 명령)에서 분기한다. | `unknown` |

문자열과 BigInt는 **처음 11개 네이티브 명령만** 기록했다. 따라서 분기 시작과 결과는 확인했지만 그 뒤의 전체 상태 전이는 아직 요약하지 않았다. Python 252와 JavaScript 숫자 252는 다음 핸들러까지 기록했다. `unknown`은 해당 의미를 복구했다는 뜻이 아니라 현재 요약 적용을 거부했다는 뜻이다.

## 증거 수준과 남은 한계

- 소스 경로는 실제 명령의 Ghidra Low P-code를 심볼 입력으로 재생해 조건식·상태식·효과식을 얻었다. 새 경로는 저장한 식으로 차등 검증했다. Lua 원래 요약의 증거 수준과 Python 숫자값의 고정 주소 전제는 각각 기존 문서에 따른다.
- JavaScript의 `X+5`와 슬롯 쓰기, Python의 cached-int 숫자 결과는 별도 SMT 반례 부재 검사 근거가 있다. 하지만 현재의 전체 상태 전이 요약은 **관측된 경로에 도달한다는 조건 아래의 부분 정확성**이다. 관측하지 않은 경로의 완전성, 예외 처리, 임의 객체·프레임 주소에 대한 보편적 정리는 증명하지 않았다.
- Python의 12개 쓰기와 JavaScript의 슬롯 쓰기는 네이티브 효과다. 이들 모두가 원본 스크립트 관점에서 관찰 가능한 효과라는 뜻은 아니다. 프레임·참조계수·임시 스택의 불필요한 효과를 안전하게 지우려면 별도의 관찰 경계와 생존성 증명이 필요하다.
- 바이너리 해시, Python 캐시 이미지, JavaScript `--jitless` 실행 모드와 관측 경로가 맞아야 한다. JS JIT 코드 변화나 Python 적응형 코드 변경을 일반적으로 추적하는 code epoch 관리자는 아직 없다. 경로 발견과 엔진별 입력 바인딩도 현재는 실험용 adapter와 fixture에 의존한다.
- 새 대상의 첫 메모리 읽기 값과 실제 읽기·쓰기 목록은 네이티브 실행 추적에서 얻는다. 그러므로 대상 P-code 재생 0회는 **실행 없이 정적으로 결과를 예측했다는 의미가 아니다**. 실행 전 적용에는 필요한 초기 메모리 snapshot과 경로 조건을 별도로 확보해야 한다.
- `common-observed-transition-v1`은 SMT-LIB 식을 각 출력에 직렬화한다. DAG 공유·SSA 메모리 버전·호출/할당/예외 효과를 갖춘 일반적인 합성 형식으로 확장해야 한다. 범용 디컴파일 결과나 VMP 적용 성공을 주장하지 않는다.

## 다음 연구 순서

1. **새 경로의 효과까지 수집**: Python 결과 257 할당 경로, JS 문자열 연결과 BigInt 오류 경로의 전체 경계·읽기·쓰기·종료 종류를 구분한다. 같은 입력 타입의 새 프로그램에서 다시 적용하거나 `unknown`을 유지하는 기준을 세운다.
2. **경계와 입력 계약 자동화**: 수동으로 지정한 핸들러 PC와 live-in/out을 P-code 역방향 슬라이스·제어 흐름·메모리 효과 분석으로 후보화한다. `daasdmlkas`는 읽기 전용 참고 대상으로 두고, R4interpreter 안에서 adapter/API와 독립 검증을 개발한다.
3. **상태 축약과 합성**: 호출자에게 관찰되는 VM 슬롯·반환값까지 역방향 슬라이스해 죽은 네이티브 임시 쓰기를 제거한다. 보존한 쓰기에는 alias·frame 증거를 붙이고, 두 핸들러와 fetch/dispatch를 합성한다. 원본 스크립트의 분기·호출 결과와 축약된 상태 전이를 비교한다.
4. **형식 확장과 경로 범위**: `Write` 이외 `Allocate`, `Call`, `Throw`, `Havoc`의 순서와 객체 정체성, 코드 epoch를 표현한다. 경로 열거·합류·루프의 `unknown` 범위를 측정한다. 이 조건이 갖춰진 뒤 VMP의 안정적 경계를 작은 사례에서 확인한다.

## 재현

저장소 루트에서 실행한다. 현재 고정 바이너리와 추적 파일이 필요하다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_js_handler_transition.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_python_handler_transition.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/evaluate_alternate_paths.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/common_observed_transition.py
```
