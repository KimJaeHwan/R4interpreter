# Python·JavaScript 네이티브 값 계산 경로

후속 [전체 함수 경로 실험](PYTHON_JS_FULL_FLOW_RESULT.md)은 이 덧셈 식을 분기·호출·반환과 연결해 호출자에게 전달된 값까지 확인했다. 아래 내용은 덧셈 핸들러 단독 실험 시점의 결과다.

## 결과

입력 `9`로 실행한 실제 바이트코드 핸들러를 단일 명령씩 기록하고, 해당 실행 파일의 바이트를 Ghidra SLEIGH `pypcode`로 변환해 동일 경로를 재생했다. 네이티브 입력을 기호 변수 `X`로 바꾼 뒤, 실행된 분기와 메모리 주소가 같다는 조건 아래 `X+5` 식의 반례를 Z3로 찾았다. 두 엔진 모두 반례 질의가 `unsat`이고, 조건을 만족하는 다른 입력 `10`은 `sat`이다. [기계 판독 결과](cross_value_path_result.json)에 바이너리와 추적의 SHA-256을 남겼다.

| 엔진 | 값 경계 | 네이티브 명령 / Low P-code 연산 | 확인한 식 |
|---|---|---:|---|
| CPython 3.13.5 | `addFive`의 `BINARY_OP` 시작 → 다음 `RETURN_VALUE` 핸들러 | 116 / 626 | PyLong 숫자 자리의 `X + 5`; 작은 정수 캐시 주소를 결과 스택 슬롯에 저장 |
| Node 24.19.0 `--jitless` | `addFive`의 `AddSmi` 시작 → 다음 핸들러 | 23 / 122 | 결과 누산기 `RAX = (X + 5) << 32` (Smi 태그) |

Python은 `BINARY_OP`가 간접 호출한 숫자 연산 함수 `0x5e9710` 안에서 자리값을 읽고, `0x5e977d`에서 합한 후 `0x5e9780`에서 캐시 범위를 검사한다. `_PyLong_Add`라는 별도 함수를 거칠 것이라는 초기 추측은 실제 추적에서 틀렸다. `X=9`의 결과 주소는 `0xa42c70`이며, 실행 파일과 동기화 지점의 메모리에서 이 객체의 숫자값이 `14`임을 확인했다. `10..256`에 해당하는 작은 정수 캐시 247개 항목도 각 객체의 태그와 숫자 자리를 검사했다. 전체 경로의 P-code는 `5 ≤ X ≤ 251`일 때 결과 스택 슬롯이 `X+5` 항목의 주소가 됨을 보인다. 결과 캐시 영역을 기록된 경로에서 쓰지 않는 것도 확인했다.

Python의 기호 입력은 실제 관측된 캐시 객체 `9`의 숫자 자리만 바꾼 가상 메모리 상태다. 따라서 결과가 같은 객체 `9`를 가리키는 `X=4`는 이 캐시 근거로 인정하지 않는다. 입증 구간을 `5..251`로 둔 이유다. 그 밖의 다른 객체 주소, 음수, 큰 정수, 다른 연산 경로까지 포괄하는 증명은 아직 아니다. 캐시 항목의 정적 내용과 동기화 시점의 런타임 내용이 같다는 점을 확인했지만, 이 실험에서 가능한 모든 프로세스 상태를 증명한 것은 아니다.

JavaScript는 bytecode의 즉시값 `5`를 읽고, 누산기 `RAX`의 Smi 태그 검사와 산술 오버플로 검사를 통과한 뒤 `RBX`에 `(X+5)<<32`를 만든다. 해당 경로 조건은 32비트 부호 있는 덧셈 오버플로가 없음을 함의한다. 재생 후 다음 `Return` 핸들러 진입의 `RAX`도 결과 태그값 `14`와 일치했다. HeapNumber, 문자열, 객체 변환, 오버플로 뒤의 경로는 별도로 다뤄야 한다.

이 결과는 **해당 계산 핸들러의 조건부 값 식**이다. 앞서 만든 `branchCall`의 분기, 함수 호출, 반환값이 이 핸들러와 끝까지 연결된 증명은 아직 아니다. 기존 [첫 교차 실험](PYTHON_JS_FIRST_RESULT.md)의 전체 프로그램 요약 `0 → 10`, 그 외 `x+5`는 여전히 표본 기반 후보이며 이 결과만으로 증명 등급을 올리지 않는다. 다음 단계는 호출 인수·VM 스택/누산기·반환값을 연결하고, Python의 다른 PyLong 경로와 JS의 Number 경로를 독립 case로 추가하는 것이다.

## 재현과 자료

저장된 [Python 추적](artifacts/cross_python_value_9_native.json), [JavaScript 추적](artifacts/cross_js_value_9_native.json), 두 stdout 및 [증명 스크립트](prove_cross_value_path.py)를 사용한다. 저장된 추적만으로 값 경로 재생은 다음 명령으로 다시 실행할 수 있다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_cross_value_path.py \
  experiments/interpreter-expression/artifacts/cross_python_value_9_native.json \
  experiments/interpreter-expression/artifacts/cross_js_value_9_native.json
```

원시 추적을 다시 만들 때는 [추적 스크립트](trace_value_path.py)가 Linux `ptrace`와 위와 같은 SHA-256의 CPython/Node 실행 파일, 저장된 `.pyc`/JS fixture를 사용한다. 고정된 네이티브 주소는 이 두 바이너리에만 적용된다. `daasdmlkas`는 읽거나 수정하지 않았다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_value_path.py \
  python /usr/bin/python3.13 /tmp/r4_python_value_marker.json /tmp/r4_python_value.json \
  -I -S experiments/interpreter-expression/artifacts/cross_python_fixture.cpython-313.pyc \
  --mark /tmp/r4_python_value_marker.json --native-sync 9

experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/trace_value_path.py \
  javascript "$(command -v node)" /tmp/r4_js_value_marker.json /tmp/r4_js_value.json \
  --jitless --no-warnings --print-bytecode --print-bytecode-filter=addFive \
  experiments/interpreter-expression/js_branch_fixture.js \
  --mark /tmp/r4_js_value_marker.json --native-sync 9
```
