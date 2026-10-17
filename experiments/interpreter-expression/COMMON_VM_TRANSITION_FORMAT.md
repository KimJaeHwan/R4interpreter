# 공통 VM 상태 전이 요약 형식: Lua, Python, JavaScript, VMP

상태: 설계 초안. 목적은 원본 스크립트나 미리 작성한 opcode 의미표 없이, 네이티브 바이너리의 P-code에서 얻은 **한 실행 경계 사이의 상태 변화**를 같은 형식으로 표현하는 것이다. [Lua 처리 구간 실험](VM_HANDLER_SUMMARY_DESIGN.md)은 이 형식의 첫 사용 사례다. [Lua 이식 준비 결과](lua_pre_python_js_port.json)는 이 전이들에서 guard와 최종 계산식만 뽑은 언어 중립 **투영**이다. 투영에는 전체 메모리 효과가 없으므로 원본 전이 요약을 대체하지 않는다. 아래 형식 자체가 어떤 VM에서든 자동 추출에 성공한다는 뜻은 아니다.

[Python·JavaScript 첫 교차 실험](PYTHON_JS_FIRST_RESULT.md)은 이 투영에 `Z`와 `F64` 값 sort를 추가한 `portable-guarded-expression-v1` 후보를 만들었다. Lua `BV64`와 같은 case 적용기를 사용하지만 새 두 엔진의 **값 식은 아직 I/O 차등 검증 등급**이다. 두 엔진의 네이티브 fetch/dispatch는 P-code로 확인했으며, 전체 상태 전이의 효과·메모리·호출 합성까지 성공했다고 해석하지 않는다.

## 공통으로 표현할 것

모든 대상을 `상태 S에서 진입 경계 E를 지나, 조건 C 아래 상태 S'와 종료 경계 E'가 되는 전이`로 본다. 이 전이의 단위는 Lua opcode, Python opcode, JS bytecode 또는 VMP 가상 명령일 수 있지만 **핵심 형식에는 그 언어의 필드 이름을 넣지 않는다.** 경계는 간접 분배, 호출, 기본 블록 집합, JIT 진입점 등 대상에서 증명 가능한 지점으로 잡는다.

```text
TransitionSummary v0
  schema_version, semantic_model:
    architecture, endian, pointer_width, P-code/lifter version,
    supported integer/float/memory/exception semantics
  identity:
    executable_code_digest, code_object_id, code_epoch,
    entry_cutpoint, exit_cutpoints, specialization_dependencies
  interface:
    inputs = typed bitvectors/floats/references/memory and symbolic parameters
    live_in / live_out = boundary state that cannot be discarded
  cases:
    condition = typed expression over input state and code bytes
    reads = location, width, memory/state version, ordering/evidence
    effects = ordered Write / Havoc / Allocate / Free / Call / Event
    frame = proven unchanged locations, alias assumptions, clobbered regions
    successors = cutpoint | return | call | throw | yield | deopt |
                 proved divergence | unknown
                 each with target expression and successor state
    assumptions, unresolved, evidence, validation_level,
    termination_claim = partial | total_proved | unknown
  uncovered:
    unknown(reason), analysis bounds; no implicit fallthrough or frame claim
```

`location`은 이름 붙은 변수 하나가 아니라 **주소 공간·주소식·폭**으로 표현한다. 네이티브 레지스터의 바이트 조각, VM 스택, 힙, 바이트코드 버퍼, 숨은 런타임 상태가 같은 메커니즘을 사용한다. 초기 구현 범위는 단일 스레드의 바이트 단위 메모리와 비트벡터다. 객체 정체성, property lookup, Python/JS 값은 필요할 때 참조·opaque sort·검증된 함수 요약으로 확장한다. 설명되지 않은 helper 호출을 자유로운 수학 함수로 놓고 증명된 결과처럼 취급하지 않는다.

식은 **비트폭과 연산별 signed/unsigned 의미**를 명시한 P-code 연산, 메모리 읽기, `ite`, 비교, 참조 동일성 등을 표현한다. 공유되는 부분식은 DAG/SSA 노드로 보존해 요약을 합성할 때 매번 거대한 식으로 펼치지 않는다. byte order, 부분 쓰기, alias, 효과 순서를 보존한다. 예를 들어 `Load(M_i, a, 8)`은 특정 메모리 버전 `M_i`를 읽고, `Store` 뒤에는 `M_{i+1}`을 사용한다. 별도 `reads` 목록도 이 버전을 가리켜야 한다. `Write`가 없는 영역을 자동으로 보존한다고 가정하지 않는다. `frame`은 P-code 효과 또는 명시한 전제로 입증한 영역에만 쓴다. 알 수 없는 쓰기·호출은 영향 가능한 상태를 `Havoc`으로 표시하거나 그 사례를 `unknown`으로 끝낸다. 예외·재진입·입출력·비결정성은 단일 반환값이 아니라 효과와 복수의 가능한 종료로 나타낸다.

`identity`는 **분석한 실행 코드의 버전**을 포함한다. Python의 적응형 바이트코드, JS의 JIT·deopt, VMP의 자체 수정 코드가 바뀌면 예전 P-code 요약을 그대로 재사용하지 않는다. 변경된 코드의 새 해시/epoch에 다시 연결하거나, 버전 간 관계를 별도로 증명한다. 실행 파일의 해시만으로 JIT 코드나 실행 중 바뀐 코드를 식별했다고 주장하지 않는다.

재사용할 바이트코드의 내용은 가능한 한 **심볼 입력**으로 남기고, 다른 `.luac`마다 요약 identity를 새로 만들지 않는다. 반대로 bytecode, decode table, inline cache 값을 구체 상수로 사용했다면 `specialization_dependencies`에 기록한다. 그 값이나 실행 코드가 바뀌면 요약을 무효화한다. 변경을 감지할 수 없다면 `unknown(code validity)`이다.

## 사례 조건과 증거 수준

한 요약은 여러 case를 가질 수 있다. 예를 들어 정수 fast path와 객체 연산 호출 path는 조건과 효과가 다르다. 모든 case를 분석할 필요는 없지만, 다루지 않은 조건은 명시적으로 `unknown`이다. case의 조건은 실제 P-code 분기와 상태 읽기에서 유도한다. **실행된 PC 목록만으로 미래 입력을 판정하는 조건을 만들지 않는다.** 두 case의 조건이 동시에 참이면 가능한 전이를 모두 보존한다. 결정적이어야 할 두 case의 결과가 충돌하면 요약 오류 또는 미해결로 보고하며, 임의의 우선순위로 하나를 선택하지 않는다.

각 case에는 P-code 연산 키, 분기 근거, 메모리 버전·호출 모델, 동적 검증 기록과 빠진 부분을 연결한다. 판정 등급은 다음을 구분한다.

| 등급 | 뜻 |
|---|---|
| `candidate` | 추출한 전이지만 효과·조건에 미해결 부분이 있다 |
| `differentially validated` | 별도 입력/프로그램의 경계 상태와 효과가 일치했다 |
| `proved under preconditions` | 적힌 전제와 모델 아래에서 해당 case의 P-code 전이가 충족됨을 보였다 |

SMT가 식 `X+7`의 대수를 확인했더라도 생략한 메모리 효과가 있으면 세 번째 등급으로 올리지 않는다. `proved under preconditions`는 기본적으로 **해당 종료 경계에 도달했을 때 전이가 맞다는 부분 정확성**이다. 반드시 종료한다는 주장은 별도 종료 증명이 있을 때만 붙인다. 분석 예산이나 루프 상한 초과의 `unknown`을 실제 무한 반복(`proved divergence`)으로 표시하지 않는다. 요약은 `unknown` 사례와 미해결 효과를 삭제하지 않은 채 합성한다.

## 합성 규칙

요약 `A`의 종료 경계와 `B`의 진입 경계가 같고, semantic model과 코드 epoch·특수화 의존성이 호환되며, `A`의 출력 상태가 `B`의 모든 live-in을 제공할 때만 바로 합성한다. `B`의 전제도 증명하거나 합성 결과의 조건으로 남겨야 한다. 충족 여부를 알 수 없으면 잔여 `unknown` 경로를 유지한다. 경계가 다르면 사이의 fetch/decode/dispatch 또는 호출 전이를 별도 요약으로 연결한다. 조건은 상태 치환 후 결합하고, 쓰기 효과는 순서대로 적용한다. 분기가 합류하면 guard와 이전 경로의 대응이 확인된 호환 상태에 한해 `ite`/phi로 합친다. 루프의 일반식은 불변식 또는 명시한 유한 범위가 없으면 주장하지 않는다.

이 규칙 덕분에 **공통 형식은 같아도 경계 발견과 상태 대응은 대상별 작업**으로 남는다. 첫 단계에서는 작은 설정/seed가 필요할 수 있다. 공통 P-code 식 평가기, 메모리 모델, 조건·효과·합성기는 공유하고, 언어별 의미표를 분석기에 미리 넣지 않는다. adapter가 제공한 발견 힌트·수작업 경계는 증거에 표시한다. 엔진 구조를 찾는 힌트와 `opcode 21 = 덧셈` 같은 의미 정답표는 구별한다.

## 대상별로 달라지는 발견 작업

| 대상 | 경계·상태 후보 | 공통 형식에 남겨야 할 특이 효과 |
|---|---|---|
| Lua 인터프리터 | 바이트코드 읽기와 간접 분배, VM 메모리 슬롯 후보 | 타입 분기, 호출·오류, 코드 포인터 변화 |
| Python 인터프리터 | 명령 읽기/분배 또는 tier별 진입점, frame/value stack | 예외, 적응형 명령의 코드 epoch, helper 호출·객체 참조 |
| JavaScript 인터프리터 | 선택한 엔진의 bytecode 분배 경계와 실행 frame | 객체/프로퍼티 효과, 예외, JIT 진입·deopt·코드 버전 |
| VMP | 관측 가능한 가상 상태 갱신과 재분배 후보 | 복호화 키·코드 변형, 간접 분기, 불안정한 경계는 `unknown` |

이 표는 opcode 뜻을 제공하는 분석 규칙이 아니다. 각 후보가 실제 바이너리에서 성립하는지 P-code와 관측으로 확인한다. Python과 JS 엔진은 버전과 실행 tier에 따라 구조가 다르므로, 처음에는 **한 버전·한 tier의 인터프리터 모드**로 제한하고 나중에 요약을 추가한다. VMP에서 안정적인 경계나 상태를 찾지 못하면 형식은 사용할 수 있어도 신뢰할 요약을 생성하지 못한다. 이는 포맷 실패가 아니라 추출/검증 한계로 보고한다.

Lua의 `add64`는 Lua 실험의 네이티브 정수 경로에서만 나온다. Python 정수는 임의 정밀도일 수 있고, JS에서는 IEEE 754 부동소수점의 NaN·부호 있는 0, 타입 변환, 객체 효과가 중요하다. 이들을 64비트 덧셈이나 수학적 실수 덧셈으로 바꿔 공통 의미라고 주장하지 않는다. GC로 이동하는 객체의 동일성도 단순 주소값과 분리해야 한다. 지원하지 않는 연산은 공통 형식의 `unknown`/미지원 효과로 나타낸다.

VMP의 가상 PC와 복호화 키가 상태에 따라 바뀐다면 그 값도 입력 상태와 decode 전이에 포함한다. numeric opcode 하나를 전역 identity로 사용하지 않는다. 코드 변경을 추적할 수 없거나 분배 지점을 확정할 수 없는 구간은 캐시된 요약으로 처리하지 않는다.

## 공통성 검증 순서

1. [Lua 첫 관문](VM_HANDLER_SUMMARY_DESIGN.md)에서 `W`, 상태 위치, 조건, 효과, 종료 경계를 모두 **이 형식으로 저장**한다. `lua_opcode`, `TValue` 같은 필수 핵심 필드를 만들지 않는다. `x+7` 요약을 동결한 뒤 `x+11`에 적용한다. 요약을 별도 loader/evaluator에서 읽어 적용하고, evaluator에 Lua opcode 분기문을 넣지 않는다.
2. 기존의 작은 네이티브 ELF 산술 사례도 **같은 직렬화 형식과 evaluator**에 넣는다. 이때 Lua 전용 새 필드나 opcode 규칙 없이 결과를 적용해야 한다. 이는 첫 번째 이식성 확인일 뿐, Python/JS/VMP 분석 성공은 아니다.
3. Python의 고정된 인터프리터 버전과 작은 정수 바이트코드에서 새 분석 대상 adapter로 경계·입출력 위치를 찾는다. 핵심 형식과 식/효과 합성 코드를 바꾸지 않고 같은 종류의 요약 파일을 생성하는지 본다. 객체 읽기나 helper 호출이 있는 짧은 사례도 넣어 `unknown` 또는 효과 표현이 충분한지 검사한다. 필요한 새 효과가 있다면 근거와 함께 형식을 버전업한다.
4. JIT을 끈 단일 JS 엔진에서도 같은 검사를 반복한다. 객체/프로퍼티 또는 예외 사례는 별도 case/unknown으로 남기고 정수 경로의 성공과 구분한다.
5. VMP는 안정적인 가상 경계와 코드 epoch가 관측되는 소형 사례부터 시작한다. 난독화·자체 수정 때문에 경계 추출이 안 되면 억지 요약을 만들지 않고 실패 원인을 측정한다.

단계별 지표는 **핵심 형식 변경 수, 공통 엔진 코드 재사용량, 대상별 설정·수작업량, 정의된 case의 정확성, `unknown` 범위, 추출/적용 비용**이다. 한 대상에서 같은 JSON 모양만 출력하는 것은 충분하지 않다. 다른 대상에도 같은 검증 규칙과 합성 의미가 적용돼야 공통 포맷이라고 판정한다.
