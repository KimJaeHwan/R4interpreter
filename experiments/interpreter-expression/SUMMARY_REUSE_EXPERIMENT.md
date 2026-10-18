# Python·JavaScript 값 요약 재사용 실험

이 실험은 CPython 3.13.5와 Node 24.19.0 `--jitless`의 저장된 네이티브 실행을 Ghidra SLEIGH Low P-code로 분석한다. 요약을 만든 실행과 별도 실행에서 **입력값으로 결과를 예측하고 대상 구간의 P-code를 다시 재생하지 않는지** 확인했다. 모든 승인은 아래에 적은 관측 경로와 고정된 바이너리에 한정한다. `daasdmlkas`는 기준 커밋 `3a274f93d455d3caaebf72365e64820770341787`을 읽기 전용으로 사용했다.

아래 여섯 단계는 각각 구현·결과 재계산 후 Astra의 별도 검토를 통과했다. 검토의 승인 범위도 관측 경로의 제한적 실험이며 언어별 모든 경로의 완전성은 포함하지 않는다.

## 단계별 결과

| 단계 | 결과 | 범위 |
|---|---|---|
| 1. JavaScript 요약 재사용 | `twoAdds`의 첫 `AddSmi` 앞부분 11개 네이티브 명령, 78개 P-code 연산을 요약해 다음 바이트코드 위치에 적용. 두 번째 입력 `14`의 앞부분 결과 `19`를 대상 P-code 재생 0회로 확인 | Smi `5 ≤ X ≤ 251`, 즉시값 `5`, 읽기 주소·바이너리·다음 주소·16개 일반 레지스터·5개 플래그 검사. 전체 핸들러는 제외 |
| 2. 결과부터 역방향 선택 | 호출자가 받은 `RAX`에서 시작해 부모 인수 읽기 → 자식 인수 슬롯 쓰기·읽기 → 덧셈 → 결과 반환 4개 지점을 발견 | JavaScript 입력 `9`의 25,104개 네이티브 단계 중 104개, 207개 P-code 연산 선택. `daasdmlkas`의 국소 SSA 슬라이스는 78개 중 14개 연산 선택 |
| 3. 경계 발견 | 관측된 간접 분배에서 핸들러 진입, 덧셈 후 첫 조건 분기에서 요약 종료, 다음 간접 분배에서 핸들러 종료를 찾음 | `0x1bb7780 → 0x1bb77ab` 11개 명령의 공통 앞부분. 두 위치의 핸들러 출구는 각각 다시 `AddSmi`, `Return`으로 연결 |
| 4. Python 값 요약 | 원본 입력값 `9`에서 `X+5` 숫자식을 P-code와 Z3로 증명하고, 다른 객체·프레임 주소의 입력값 `5`에 저장된 JSON 식을 적용해 `10` 예측 | 원본 116개 네이티브 명령·626개 P-code 연산. 대상 P-code 재생 0회. 객체 주소는 공개 값 식에 포함하지 않음 |
| 5. 적용 판정 | 코드·경계·읽기·쓰기·상태·출력 목록·타입·캐시·입력 범위를 검사하고 미지원 요청은 `unknown` | Python의 숫자값 결과 쓰기 1개를 확인했지만 다른 네이티브 쓰기 11개는 미모델링. 전체 전이 적용은 `unknown` |
| 6. 새 프로그램 평가 | 별도의 `wrappedAdd` 프로그램에서 각 엔진의 입력 `37`, `251`, `252` 평가 | 엔진당 3건 중 **2건 정확 적용, 1건 `unknown`, 불일치 0건**. 적용한 대상의 P-code 재생 0회 |

2단계의 전체 경로 슬라이스는 부모 입력 위치의 8바이트와 런타임 데이터·생성 코드 쪽의 9바이트를 진입 출처로 기록한다. `js_caller_backward_slice_result.json`에는 선택에서 제외한 네이티브 메모리 쓰기 4,559개와 호출·분기·opaque P-code 연산의 수와 예시를 보관했다. 선택된 값 경로에는 미해결 읽기나 instruction 내부 분기가 없었지만, **제외된 호출의 부작용이나 다른 실행 경로가 무해하다는 일반 증명은 아니다.** 부모·자식 인수 슬롯의 관측 구간에는 하드웨어 감시점의 쓰기 적중이 없었다.

3단계의 직전 간접 분기와 덧셈 후 첫 조건 분기는 **경계 후보를 고르는 규칙**이다. 두 실험 위치와 전체 호출 경로에서 같은 명령 바이트·후속 주소를 비교했으며, 정적 CFG 전체나 다른 핸들러 출구의 완전성을 확인하지 않았다.

4단계의 Python 원본 증명은 원본 객체 주소·프레임과 다른 네이티브 상태를 고정하고 객체의 숫자 자리만 `X`로 바꿔 `5 ≤ X ≤ 251`을 증명한다. 대상은 다른 객체·스택 위치에서의 **구체적 차등 검증**이다. 임의의 객체 주소 재배치 또는 전체 Python 핸들러 대체에 대한 정리가 아니다. JavaScript 요약도 산술 앞부분의 레지스터·플래그·읽기만 포함한다. 전체 함수 반환 연결은 기존 [전체 경로 결과](PYTHON_JS_FULL_FLOW_RESULT.md)의 별도 조건부 증명이다.

## 새 프로그램 평가

| 엔진 | 입력 37 | 입력 251 | 입력 252 | 적용/`unknown`/불일치 |
|---|---|---|---|---|
| JavaScript | 예측·실행 `42` | 예측·실행 `256` | 실행 `257`, 요약은 `unknown` | 2 / 1 / 0 |
| Python | 예측·실행 `42` | 예측·실행 `256` | 실행 `257`, 요약은 `unknown` | 2 / 1 / 0 |

JavaScript는 세 입력 모두 11개 네이티브 명령의 앞부분을 기록했다. Python은 증명 범위의 두 입력에서 각각 116개 명령을 기록하고 대상 프로세스의 작은 정수 캐시 전체 해시를 핸들러 진입·종료 시 확인했다. 캐시 영역과 겹치는 네이티브 쓰기는 없었다. Python 입력 `252`는 프로그램 출력만 별도 실행으로 재확인했고 네이티브 경로는 기록하지 않았다. 따라서 `unknown`은 미지원 범위를 정확하게 표시한 것이며 그 경로의 내부 동작을 설명한 것으로 세지 않는다. [사례별 판정](summary_holdout_result.json)에 해시와 기록 단계 수를 보관했다.

## 파일과 재현

- [호출 결과 역방향 선택](slice_js_caller_result.py) → [결과](js_caller_backward_slice_result.json), [경계 발견](discover_js_boundaries.py) → [결과](js_boundary_discovery_result.json), [국소 SSA 선택](slice_js_summary_reuse.py) → [결과](js_slice_selection_result.json).
- [JavaScript 요약 증명·재사용](prove_js_summary_reuse.py) → [요약](js_addsmi_prefix_summary.json)·[결과](js_summary_reuse_result.json). 원시 추적은 `artifacts/js_summary_reuse_9.json.gz`.
- [Python 숫자 요약 증명·재사용](prove_python_value_reuse.py) → [요약](python_numeric_value_summary.json)·[결과](python_numeric_value_reuse_result.json). 기존 전체 경로 추적 `artifacts/cross_python_full_{0,9}.json.gz`를 사용한다.
- [적용·`unknown` 사례](evaluate_summary_applicability.py) → [결과](summary_applicability_result.json). [새 프로그램 채점](evaluate_holdout_programs.py) → [결과](summary_holdout_result.json).
- 새 평가용 프로그램 `js_holdout_fixture.js`, `python_holdout_fixture.py`; 추적기 `trace_js_holdout.py`, `trace_python_holdout.py`. 대상 원시 추적은 `artifacts/{js,python}_holdout_*.json.gz`.

저장된 원시 추적과 고정된 바이너리가 있는 환경에서는 저장소 루트에서 다음 순서로 결과를 다시 계산한다. `daasdmlkas` 체크아웃은 읽기만 한다.

```bash
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/slice_js_caller_result.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/discover_js_boundaries.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/slice_js_summary_reuse.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_js_summary_reuse.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/prove_python_value_reuse.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/evaluate_summary_applicability.py
experiments/vm-transition-testbed/.venv/bin/python experiments/interpreter-expression/evaluate_holdout_programs.py
```

다음 분석은 Python의 나머지 11개 쓰기와 JavaScript의 산술 뒤 핸들러 구간을 효과·분기 조건으로 모델링하는 것이다. 이후 새 객체 타입·오류·호출·루프 경로에서 경계 규칙과 요약 적용 조건을 확장해야 한다. 이 단계까지는 Lua·Python·JavaScript 또는 VMP에 모두 적용할 수 있는 완전한 요약을 얻었다고 말할 수 없다.
