# 네이티브 P-code에서 입력 수준 계산식으로 축약

같은 [`logic_projection.py`](../../interpreter-expression/logic_projection.py)가 작은 R4VM과 Lua 5.4 실행기의 동결된 조건부 P-code 전이에 입력 기호 `X`를 대입하고, 읽기·순서 있는 쓰기·경로 조건을 합성한다. 사용하지 않는 네이티브 레지스터와 중간 메모리 식은 최종 값/VM 쓰기 투영에서 빠진다. `X+7`처럼 줄인 식은 원래 비트벡터 식과 **SMT로 동치임을 확인한 경우에만** 채택한다. `X`는 64비트 값이며 덧셈·뺄셈은 `mod 2^64`이다.

분석기에는 원본 C/Lua 스크립트, VM opcode 의미표, 케이스 매니페스트, 정답 파일을 전달하지 않는다. 입력은 동결된 P-code 경로 요약, 해당 ELF와 VM 바이트코드, 경계 상태용 보관 추적이다. 추적에서 얻은 경로가 적용될 조건을 식으로 보존하며, 경로 전체의 완전성은 아직 증명하지 않았다.

## 작은 VM의 프로그램별 투영

| 바이트코드 | 추출한 입력 수준 결과 | 함께 보존한 효과 |
|---|---|---|
| VMT001 | `X + 7` | 슬롯 0 쓰기, 다음 PC 2 |
| VMT002 | `X + 11` | 같은 네이티브 경로 재사용 |
| VMT003 | `X + 7` | 슬롯 이동 뒤 읽기 |
| VMT004 | `X + 18` | 두 덧셈의 순서 있는 쓰기 |
| VMT005 | `X - 7` | 피연산자 순서와 64비트 래핑 |
| VMT006 | `X ^ 85` | XOR의 비트벡터 의미 |
| VMT007 | `X == 0 → 42`, `X != 0 → X + 7` | 분기별 다른 PC와 쓰기 |
| VMT008 | `X + 18` | 같은 슬롯에 두 번 쓰기 |
| VMT009 | `type_error` | 태그 변경 뒤 오류, 숫자 결과 없음 |
| VMT010 | `unknown` | 미모델링 네이티브 호출 |
| VMT011 | `bad_opcode` | 잘못된 분배 경로 |
| VMT012 | `X + 3` | 세 번 반복한 경로와 7개 쓰기 |

각 결과의 정확한 SMT 식, 적용 조건, 네이티브 경로 ID, 순서 있는 쓰기 및 코드 해시는 [`input-logic-projection.json`](input-logic-projection.json)에 있다. 별도 정답 파일의 30개 R4VM 입력을 식에 대입한 [`input-logic-grade.json`](input-logic-grade.json)은 **28 pass, 2 accepted_unknown, 0 fail**이다. 두 `unknown`은 VMT010의 호출 경로다. 그레이더는 분석기와 별도 파일이며 `result`, 다음 PC, 순서 있는 슬롯·값·태그까지 대조한다.

## Lua에서 같은 투영기 재사용

동결된 **한 Lua 핸들러 요약**을 두 바이트코드 워드에 적용하면 첫 값 갱신은 각각 `X+7`, `X+11`이다. 보관된 경계 추적 16개(각 8개)에서 동일한 식이 나왔다. `x+7; +11` 사례에는 첫 핸들러와 다음 명령의 실제 네이티브 fetch·dispatch 요약을 합성한 뒤 같은 핸들러 요약을 다시 적용했다. 첫 값은 `X+7`, 둘째 값은 **`X+18`**이다. 보관 추적 6개에서 같은 식이 나왔고, 두 번째 핸들러의 관측 스택 상태를 계산 입력으로 사용하지 않았다. 바이트코드 읽기 주소와 읽기 전용 ELF 점프 테이블 주소는 경계 adapter가 연결했다. 결과와 입력별 재사용 기록은 같은 JSON의 `lua_handler_paths`, `lua_handler_reuse`, `lua_two_adds_path`, `lua_two_adds_reuse`에 있다.

Lua의 이 투영은 마지막 handler 갱신까지이며 **Lua 함수 반환과 스크립트 전체 효과의 증명은 아니다**. Lua 초기 입력을 `R_RDX`와 VM 스택 `R_RBX`의 첫 8바이트에 대응시키는 부분, R4VM 루프 진입 상태와 출력 ABI는 대상별 수동 adapter다. 상류의 경로 추출기도 현재 Lua와 R4VM에 별도로 존재한다. 이번에 공통화한 부분은 이미 추출된 P-code 전이를 입력 식·조건·효과로 합성하고 축약하는 단계다.

SMT 동치성은 **추출한 경로의 결과식과 짧은 식 사이**에 관한 것이다. 다른 네이티브 경로, 별칭·frame 보존, 입력 전체에 대한 guard 완전성까지 증명하지 않는다. 따라서 `guard: true`는 해당 관측 경로의 조건식이 이 프로그램·경계 상태에서 `true`로 줄었다는 뜻이다. 프로그램의 모든 실행이 그 경로를 지난다는 뜻은 아니다.

## 재현

[`README.md`](../README.md)의 Python 환경을 만든 뒤 테스트베드 디렉터리에서 실행한다.

```bash
.venv/bin/python tools/restore_frozen_binary.py
.venv/bin/python tools/run_logic_projection.py
.venv/bin/python tools/compare_logic_projection.py
```

첫 명령은 동결 R4VM ELF의 해시를 맞춘다. 두 번째 명령은 현재 요약과 보관 추적에서 입력 수준 식을 만들며, 세 번째 명령은 별도 정답에 식을 적용한다. 이 축약 단계를 실행할 때 Ghidra, C 컴파일러, `daasdmlkas` 저장소는 필요하지 않다.

다음 단계는 Lua와 작은 VM의 **상류 경로 추출 형식**을 합치고, 경계·입력 위치를 P-code/SSA 근거에서 찾는 것이다. 그 후 오류/호출/객체 효과를 늘리면서 Python과 JavaScript에 같은 축약기를 적용한다.
