# Python·JavaScript 첫 교차 실험

## 결론과 증거 수준

같은 분기·호출·반환 프로그램을 CPython 3.13.5와 Node 24.19.0의 `--jitless` Ignition에서 실행했다. Python은 해시 기반 `.pyc`를 실행했고, JavaScript는 V8이 출력한 바이트코드의 명령 바이트·주소를 기록했다. 평가용 [Python 소스](python_branch_fixture.py)와 [JavaScript 소스](js_branch_fixture.js)는 정답 대조용이다. 관측 코드와 공통 적용기는 이 소스를 opcode 의미표로 읽지 않는다.

| 구간 | Python | JavaScript |
|---|---|---|
| 바이트코드와 네이티브 분배 대응 | 코드 객체 주소를 native frame에 대조하고, 읽은 opcode byte·간접 점프 대상 기록 | BytecodeArray의 주소·opcode byte·dispatch table의 handler 주소를 기록 |
| 네이티브 P-code | CPython fetch→table load→간접 점프 6개 명령, 14개 Low P-code 연산 | Ignition fetch→table load→간접 호출 3개 명령, 13개 Low P-code 연산 |
| 분기 경로 관측 | 입력 0과 9 각각 `branchCall` dispatch 8회, `addFive` dispatch 5회 | 입력 0과 9에서 `branchCall` handler 진입 7회·6회; 별도 실행의 `addFive` 진입 3회 |
| 입력→출력 식 | `0 → 10`, 그 외 `x+5`의 **표본 기반 후보** | 동일한 모양의 **표본 기반 후보**. Number를 IEEE 754 binary64로 표시 |

[P-code 기록](cross_dispatch_pcode.json)은 실행 파일의 실제 바이트를 Ghidra SLEIGH 기반 `pypcode`로 변환했다. Python에서 `*[RBP]`의 16비트 word를 읽어 하위 opcode byte로 테이블을 조회하고 `BRANCHIND`로 이동한다. Ignition에서는 `*[R12+R9]`의 byte로 dispatch table을 조회해 `CALLIND`로 handler에 들어간다. `ptrace` 실행 기록의 opcode byte와 handler 주소가 해당 정적 구조에 맞는지 확인했다. 이것은 **분배 구간만의** P-code 분석이다. 전체 함수의 Ghidra Bundle·SSA나 값 계산 경로의 P-code 재생은 아직 없다.

[Python 후보 요약](python_portable_case.json)과 [JavaScript 후보 요약](javascript_portable_case.json)은 `portable-guarded-expression-v1` 형식이다. 두 case의 guard/결과식 트리는 같고 값 sort만 Python `Z`(임의 정밀도 정수), JavaScript `F64`(Number)로 다르다. 후보 `0 → 10`, 그 외 `x+5`는 실행 결과 `0, 1, 9`에서 맞춰 만들고 `-1, 42, 9007199254740986`에서 별도로 확인했다. Python은 `9007199254740993`과 `2^70`도 확인했다. Python 8개·JavaScript 6개, 총 14개 출력이 일치했다. 이는 **차등 검증**이며 임의의 입력·VM 상태에서 조건과 값 식이 성립한다는 증명은 아니다. [공통 적용기](portable_guard_eval.py)가 이 두 파일과 기존 [Lua BV64 결과](lua_pre_python_js_port.json)를 그대로 판정했으며, Lua 입력 9의 결과 14도 재확인했다. 적용기는 인정되지 않은 입력 2, 다른 실행 파일 해시, 객체 입력을 `unknown`으로 돌려준다.

## 실행 경로에서 확인한 세부 사항

Python의 [opcode 실행 기록](artifacts/cross_python_9_opcodes.json)에는 `COMPARE_OP`, 분기, `CALL`, `addFive`의 `BINARY_OP`, `RETURN_VALUE`가 있다. native dispatch 기록에서는 이 실행의 opcode 바이트가 해당 code object의 바이트와 맞는다. `branchCall`의 마지막 `RETURN_VALUE` offset 34/56은 설치한 170개 공통 indirect-jump 지점에서 잡히지 않았다. Python의 opcode trace에는 존재한다. 따라서 native dispatch 기록만으로 호출·반환 경계가 완전히 덮였다고 말하지 않는다.

JavaScript의 [9 경로 바이트코드](artifacts/cross_js_branch_9_bytecode.txt)에는 `TestEqualStrict`, `JumpIfFalse`, `CallUndefinedReceiver1`, `Return`이 있고, [덧셈 함수 바이트코드](artifacts/cross_js_add_9_bytecode.txt)에는 `AddSmi`가 있다. 실제 handler 진입점과 table 값이 일치했다. `Star0` 같은 짧은 명령은 앞 handler가 내부에서 처리해 독립 handler 진입 기록이 없다. 이는 앞 handler의 추가 [P-code 구간](cross_dispatch_pcode.json)에 저장(`STORE`)과 다음 bytecode fetch·간접 점프가 같이 있는 것으로도 확인했다. 비실행 분기의 정적 명령도 기록에는 나타나지 않는다. 빠진 offset 목록은 요약 JSON에 그대로 남겼다.

타입 차이를 숨기면 공통 식이 틀린다. 객체 입력에서 Python은 `__eq__`와 `__add__`를 거쳐 효과 카운터 2를 남겼고, JavaScript는 엄격 비교 뒤 `valueOf`를 거쳐 1을 남겼다. 두 출력은 우연히 6이지만 객체 case를 `unknown`으로 분류했다. 텍스트 `9007199254740993`에서는 Python 결과가 `9007199254740998`, JavaScript Number 결과가 `9007199254740996`이었다. JS 요약은 안전 정수 범위와 실제 확인한 입력만 인정한다. 정수 바깥, 예외, 암묵적 타입 변환, JIT/deopt, 새 코드 버전도 `unknown`이다.

## 지금 가능한 것과 다음 차이

공유된 부분은 **P-code로 표현 가능한 네이티브 fetch/dispatch 구조**, 값 sort를 표시한 guard/결과식 포맷, 동일한 case 적용·미확인 판정 규칙이다. 언어별 adapter는 Python의 code object/frame 및 JS BytecodeArray/handler table 주소를 찾는다. 원본 스크립트를 복구하거나 opcode 의미표를 공통 적용기에 넣지 않았다.

아직 계산 후보 자체는 입력과 출력 표본에서 맞춘 것이다. Lua 때와 같은 증명 등급을 얻으려면 Python의 정수 객체 연산과 반환, JS의 Smi/Number 핸들러와 호출/반환에서 **VM 입력 값 → 계산 → 출력 값**을 메모리·태그·예외 효과와 함께 P-code로 연결해야 한다. 현재 두 요약은 그 구간을 증명한 것처럼 표시하지 않는다. 다음 실험은 우선 Python의 작은 정수 경로와 JS `AddSmi` 경로 각각 한 개를 추적해 `x+5`의 native 값 식을 도출하고, 타입 분기·overflow를 별도 case 또는 `unknown`으로 남기는 것이다.

## 재현

고정 주소는 위의 CPython/Node 실행 파일 버전과 SHA-256에만 유효하다. 다른 바이너리는 새 경계를 찾아야 한다. Linux x86-64에서 저장소 루트 기준:

```bash
experiments/vm-transition-testbed/.venv/bin/python -m pip install -r experiments/interpreter-expression/requirements-cross-language.txt
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/cross_dispatch_pcode.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/collect_cross_language.py
```

실험은 읽기 전용으로 `daasdmlkas`의 어떤 파일도 사용하거나 바꾸지 않는다. 이 저장소의 [종합 결과](cross_language_result.json), 요약 두 개, `artifacts/cross_*` 압축 원시 추적과 bytecode 출력이 재검토 자료다. native 수집에는 Linux `ptrace` 권한이 필요하다.
