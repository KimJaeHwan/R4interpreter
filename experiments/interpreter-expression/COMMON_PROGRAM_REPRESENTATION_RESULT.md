# 공통 프로그램 표현 IL: 검증된 범위

`common_program_representation_v1.json`은 Python·Lua·JavaScript에서 검증한 여섯 단위를 같은 노드 어휘로 표현한다. 작은 `BV32` 값 DAG는 평가할 수 있다. 네이티브 노드는 저장된 가드·효과, 관측 원장, 검증 증명서와 실제 평가기 참조를 함께 갖지만 이 JSON만으로 독립 실행되지는 않는다.

Python의 네 단위는 각 입력의 **전체 관측 네이티브 경로**이다. Lua와 JavaScript는 각각 **한 핸들러 구간**이며 호출자에서 함수 반환까지의 경로로 합성한 것이 아니다. 모든 입력·환경·분기·예외를 포괄하는 프로그램은 아직 아니다.

| 단위 | 적용 범위 | 네이티브 명령 | 노드 | 미해결 의무 |
|---|---|---:|---:|---:|
| python_251 | selected_full_native_path | 987 | 6 | 131 |
| python_252 | selected_full_native_path | 1017 | 6 | 139 |
| python_254 | selected_full_native_path | 1017 | 6 | 139 |
| python_255 | selected_full_native_path | 1017 | 6 | 139 |
| lua_segment | single_handler_segment | 23 | 1 | 3 |
| javascript_segment | single_handler_segment | 23 | 1 | 5 |

## 표현 예

```text
value library: BV32 Y := X + 5  (각 언어 어댑터가 증명한 입력 영역에서만)
Python exact witness: PcodeWindow -> CheckedExternalEffect(libc zero8) ->
  PcodeWindow -> GuardedNativeTransition -> GuardedNativeTransition -> PcodeWindow
Lua exact segment: GuardedNativeTransition -> UnknownEnclosingProgram
JavaScript exact segment: GuardedNativeTransition -> UnknownEnclosingProgram
각 단위: UnknownEdge / UnknownExceptionEdge / UnknownLifetime (해당할 때)
```

Lua의 선택된 `plus11` 핸들러에 `X+5` 값을 억지로 연결하지 않는다. 값 라이브러리의 공통 `X+5`는 별도 Lua·Python·JavaScript 어댑터와 그 입력 영역의 증명에 연결된다. Python 경로의 출력 값은 네 정확한 입력에서 계산으로 확인했으며, 객체 할당 권한과 새 객체 여부는 별도 미해결 의무다.

libc 노드는 특정 libc 이미지의 12개 명령과 `RDX=8`, `RSI=0`, 페이지·별칭·스택 전제를 검사한 후 목적지의 **정확히 8바이트**를 0으로 기록한다. 반환 레지스터와 정의된 플래그를 적고, 정의되지 않은 PF 및 벡터·마스크 레지스터의 후속 값은 미해결로 둔다. Python 구간 연결의 `computed` 등급은 이 정확한 입력과 첫 읽기 메모리 환경에만 적용한다.

생성기는 원시 추적에서 Python 메모리 원장과 제어 목록을 다시 만들고, 기존 경로 IL의 조건부 증명서를 검증한 다음 Python 네 경로를 재적용한다. Lua·JavaScript 요약은 각각 저장된 대상 추적에 다시 적용한다. 저장된 JSON의 검증은 **같은 실행에서 원본으로 새로 만든 canonical**과 전체 비교하며, 가드·효과·출처·영역·수명 미해결 의무 등 12가지 변조를 거부한다. 해시 자체를 의미 증명으로 취급하지 않는다.

재현:

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/build_common_program_representation.py
```

## 전체 로직 복원까지 남은 일

- 현재 선택 경로 밖의 분기·호출·예외를 찾고 실행 가능성 또는 불가능성을 증명한다.
- 할당·해제·객체 별칭과 수명 효과의 권한을 확보한다.
- Lua·JavaScript의 핸들러 앞뒤 호출자 경로와 더 넓은 입력·환경을 연결한다.
- 검증된 CFG와 효과를 결합해 읽을 수 있는 전체 로직을 출력한다.
