# Python·JavaScript 분기·호출·계산·반환 연결

후속 [값 요약 재사용 실험](SUMMARY_REUSE_EXPERIMENT.md)은 JavaScript 산술 앞부분과 Python 숫자 결과를 다른 실행에 적용한다. 이 문서의 전체 함수 경로 증명을 전체 네이티브 효과의 재사용 증명으로 확대하지 않는다.

## 결론

CPython 3.13.5와 Node 24.19.0 `--jitless`에서 같은 `branchCall` fixture의 네이티브 실행을 함수 진입부터 호출자에게 복귀하는 지점까지 기록했다. Ghidra SLEIGH의 Low P-code로 분기, 호출 인수, 자식 함수의 덧셈, 두 번의 반환을 재생하고 구간별 식을 합쳤다. [기계 판독 결과](cross_full_flow_result.json)는 두 엔진 모두 다음 **조건부 함수 결과**를 확인한다.

```text
X = 0             → 10
5 ≤ X ≤ 251       → X + 5
```

| 엔진 | 실제 실행 입력 | 추적한 네이티브 명령 | 호출자에게 전달된 값 |
|---|---:|---:|---:|
| CPython | 0 | 964 | 10 |
| CPython | 9 | 987 | 14 |
| Node Ignition | 0 | 26,255 | 10 |
| Node Ignition | 9 | 25,104 | 14 |

이것은 단순히 네 출력에 식을 맞춘 결과가 아니다. 각 P-code 구간에서 기록된 레지스터·메모리 변화가 재생값과 일치해야 다음 구간으로 넘어간다. Z3는 적용 범위 안에서 실행 경로의 분기 조건을 벗어나거나 결과식과 다른 값을 만드는 반례를 찾지 못했다(`unsat`). 두 번의 `Return` 핸들러를 지나 호출자의 다음 바이트코드 분배 지점에서도 Python 객체 포인터와 JavaScript Smi 값이 그대로 전달됐다.

## 값이 이동한 경로

| 단계 | Python | JavaScript |
|---|---|---|
| 분기 | `COMPARE_OP` → `POP_JUMP_IF_FALSE`: 0은 offset 14, 비영은 offset 36 | `TestEqualStrict` → `JumpIfFalse`: 0은 offset 6, 비영은 offset 17 |
| 호출 인수 | 부모 VM 스택의 `X` 또는 상수 5가 자식 프레임의 local로 복사 | 부모 인수 또는 `LdaSmi 5`가 자식 호출 슬롯로 복사 |
| 덧셈 | 자식 `BINARY_OP`가 PyLong 자리값을 더하고 작은 정수 캐시 결과를 스택에 저장 | 자식 `AddSmi`가 태그된 누산기에 `5 << 32`를 더함 |
| 반환 | 자식과 `branchCall`의 `RETURN_VALUE`가 같은 결과 객체를 호출자 스택에 전달 | 자식과 `branchCall`의 `Return` 뒤 호출자 누산기 `RAX`가 같은 Smi 값을 유지 |

호출 중간을 단순히 전후 값이 같다는 이유로 연결하지 않았다. x86 하드웨어 감시점으로 Python의 입력 객체 태그·숫자 자리, 부모 local·호출 인수·자식 인수와 JavaScript의 부모·자식 인수 슬롯을 감시했다. JavaScript에서 자식 인수 저장부터 실제 읽기까지 약 2만 5천 명령이 있었지만, 그 사이 해당 슬롯을 읽거나 쓰는 다른 명령은 없었다. Python에서도 중간 슬롯에 예상 밖의 접근이 없었다. 분기 또는 호출 직후 입력에 의존하는 레지스터는 Python `RSI`, JavaScript `RBX` 하나씩이었고, 뒤따르는 명령이 그 레지스터를 **읽기 전에 덮어씀**을 P-code 입력 목록으로 확인했다. 그래서 이 긴 구간의 제어 흐름에 입력값이 숨겨져 남는 경로를 현재 범위에서 배제했다.

Python의 작은 정수 캐시 `10..256` 항목은 실행 파일 내용과 동기화 시점의 프로세스 메모리 SHA-256이 같고, 항목별 태그와 숫자 자리가 기대값과 맞는다. 기록된 네이티브 경로에 그 출력 캐시 항목을 쓰는 명령도 없었다. JavaScript `AddSmi` 경로에서는 부호 있는 32비트 덧셈의 오버플로가 없다는 조건을 P-code 경로 조건에서 확인했다.

## 적용 범위

분석 시작점은 **`branchCall`에 진입한 VM 인수**이며 끝점은 그 함수가 **호출자에게 값을 전달한 네이티브 분배 지점**이다. CLI 문자열을 숫자로 바꾸는 과정과 마지막 JSON 출력 직렬화는 이 P-code 연결 증명의 범위 밖이다. 기존 [교차 실험](PYTHON_JS_FIRST_RESULT.md)은 실제 프로세스 출력도 별도로 대조했다.

Python의 `5..251` 기호식은 관측한 캐시 객체 `9`의 **주소를 고정**하고 그 객체의 한 자리 숫자값을 `X`로 바꾼 VM 상태에 대한 명제다. 결과 `X+5`는 해당 입력 객체 `9`와 겹치지 않아 캐시 별칭이 생기지 않는다. 실제 CLI 입력 `5..251` 각각이 만드는 서로 다른 객체 주소의 모든 경로를 증명한 것은 아니다. 입력 `0`은 관측한 캐시 객체 `0` 상태의 별도 경로다. 따라서 [기존 portable 적용기](portable_guard_eval.py)가 새로운 CLI 입력을 아직 `unknown`으로 분류하는 것은 의도적이다.

JavaScript의 기호식은 현재 VM 상태에서 32비트 Smi 인수 `X`를 대상으로 한다. HeapNumber, 객체 변환, 문자열 결합, JIT, 다른 feedback 상태, 예외 경로는 포함하지 않는다. Python의 음수·큰 정수·다른 객체/예외 상태도 포함하지 않는다. 두 엔진 모두 다른 바이너리나 바이트코드로 옮기려면 주소와 경로를 다시 찾아야 한다. 따라서 이것은 **공통 방법으로 완성한 제한된 함수 경로**이고, 인터프리터 전체의 모든 실행을 판정하는 분석기는 아직 아니다.

## 재현

[추적기](trace_cross_full_flow.py)는 Linux `ptrace` 단일 명령 추적과 하드웨어 감시점을 사용한다. 저장된 [Python 입력 0](artifacts/cross_python_full_0.json.gz)·[9](artifacts/cross_python_full_9.json.gz), [JavaScript 입력 0](artifacts/cross_js_full_0.json.gz)·[9](artifacts/cross_js_full_9.json.gz) 추적을 재생하려면 저장소 루트에서 다음을 실행한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python \
  experiments/interpreter-expression/prove_cross_full_flow.py
```

추적을 다시 수집할 때는 [첫 값 경로 실험](PYTHON_JS_VALUE_PATH_RESULT.md)의 실행 파일 해시와 fixture를 사용한다. 아래 두 명령의 마지막 입력을 `0` 또는 `9`로 설정하면 된다.

```bash
experiments/vm-transition-testbed/.venv/bin/python \
  experiments/interpreter-expression/trace_cross_full_flow.py \
  --watch-bridge --through-return python /usr/bin/python3.13 \
  /tmp/r4_py_marker.json /tmp/r4_py_full.json.gz -I -S \
  experiments/interpreter-expression/artifacts/cross_python_fixture.cpython-313.pyc \
  --mark /tmp/r4_py_marker.json --native-sync 9

experiments/vm-transition-testbed/.venv/bin/python \
  experiments/interpreter-expression/trace_cross_full_flow.py \
  --watch-bridge --through-return javascript "$(command -v node)" \
  /tmp/r4_js_marker.json /tmp/r4_js_full.json.gz --jitless --no-warnings \
  --print-bytecode --print-bytecode-filter=branchCall \
  experiments/interpreter-expression/js_branch_fixture.js \
  --mark /tmp/r4_js_marker.json --native-sync 9
```

`daasdmlkas` 저장소는 읽거나 수정하지 않았다. 이 실험의 코드와 결과는 모두 `R4interpreter`에 저장했다.
