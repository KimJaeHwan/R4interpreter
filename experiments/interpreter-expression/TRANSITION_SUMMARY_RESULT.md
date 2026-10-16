# 첫 공통 전이 요약 실험 결과

상태: 첫 관문 통과. 이후 명령 위치·슬롯 변경과 두 처리 구간 합성은 [확장 관문 결과](TWO_HANDLER_COMPOSITION_RESULT.md)에 기록했다. [설계와 판정 기준](VM_HANDLER_SUMMARY_DESIGN.md)의 Lua 정수 fast 경로 한 개를 요약하고, 다른 바이트코드와 작은 네이티브 ELF에 같은 적용 코드를 사용했다. 이 저장소에만 코드와 증거를 저장했다. `daasdmlkas`는 수정하지 않았다.

## 무엇을 요약했나

분석 입력은 디버그 정보를 제거한 `lua_chunk.luac`와 Lua 5.4.8 실행기의 Ghidra Bundle이다. `return x + 7`의 실행 추적에서 fetch P-code `LOAD(32비트 명령) → INT_AND 127 → BRANCHIND`와 `R12 = ZeroExt(W)` 관계를 확인하고, 실제 분배 값 `21`의 처리 진입 `0x4164b8`부터 다음 읽기 직전 `0x415b24`까지의 경로를 재생했다. 처리 구간 자체는 23개 네이티브 명령이며, 그 안의 Low P-code 265개를 순서대로 평가했다.

요약에는 32비트 명령 워드 `W`, 네이티브 진입 레지스터, 초기 바이트 메모리 `M0`가 입력으로 들어간다. 분배 조건 `W&127=21`, 실제 P-code에서 얻은 태그 검사와 분기 조건, 메모리 읽기 주소·폭·버전, 순서가 있는 두 쓰기, 다음 코드 포인터, 일반 레지스터와 관측한 산술 플래그의 종료값을 식으로 저장했다. 이 경로의 P-code `LOAD`는 4개지만 같은 피연산자를 플래그 계산에 반복 사용해 실제 네이티브 메모리 읽기는 2건이다. 네이티브 쓰기는 payload 8바이트와 tag 1바이트, 총 2건이다. 관측되지 않은 함수 호출은 이 경로에 없다.

요약 파일은 [handler_summary_plus7.json](handler_summary_plus7.json)이며 [생성기](pcode_transition_summary.py)가 만든다. 적용기는 [apply_transition_summary.py](apply_transition_summary.py)이고 Lua opcode 의미표를 갖지 않는다. 비트벡터·바이트 메모리·경로 조건·효과·출력 binding만 해석한다. 식은 Z3 SMT 비트벡터식이며, 모든 메모리 쓰기는 원래 순서로 보존한다. 사례 밖은 `unknown(outside conditional path)`이다.

## 다른 바이트코드에 적용

평가용 [Lua 소스](lua_chunk_plus11_source.lua) `return x + 11`을 같은 컴파일러로 생성한 [바이트코드](lua_chunk_plus11.luac)는 원본과 길이가 76바이트다. 대상 명령 워드는 오프셋 47에서 `0x86000015 → 0x8a000015`로 바뀌었다. 두 워드의 분배 값은 `21`이고, [새 파일의 원시 명령 추적](artifacts/lua_trace_plus11_x9.csv)과 경계 추적에서 네이티브 진입 `0x4164b8`을 확인했다. `x+11`의 P-code 식을 다시 추출하거나 요약의 상수·주소를 고치지 않았다.

`x+7`과 `x+11`에 각각 `9`, `0`, `1`, `-1`, `INT64_MAX-11`, `INT64_MAX-7`, `INT64_MAX`, `INT64_MIN`을 적용했다. 총 16건 모두 요약이 `unknown` 없이 payload, tag, 실제 읽기 2건, 순서 있는 쓰기 2건, 다음 코드 포인터 및 종료 레지스터/선택 플래그를 추적과 일치시켰다. 실행기 최종 출력도 64비트 정수 래핑을 포함해 예상값과 일치했다. 학습 추적은 `x+7, x=9` 한 건이고, 다른 15건은 별도 확인이다. 예를 들어 `x+11, x=9`는 payload `20`, tag `3`; `x+11, x=INT64_MAX`의 payload는 비트패턴 `9223372036854775818`이고 실행기 출력은 부호 있는 값 `-9223372036854775798`이다.

태그가 `3`인 실제 진입 snapshot의 태그 바이트를 **시험용 사본에서만** `4`로 바꾸면 적용기가 정수 덧셈을 예측하지 않고 `unknown(outside conditional path)`을 돌려줬다. 이것은 태그 `4` 경로를 실행해 검증한 결과는 아니다.

## 공통 적용 코드 확인

작은 네이티브 ELF의 `add7` 함수 본문도 동일한 `transition-summary-v0-candidate` 구조로 [native_summary_add7.json](native_summary_add7.json)에 저장했다. 해당 Bundle의 `0x4011a0`에서 P-code `INT_ADD`와 `COPY` 2개를 재생한 결과는 `R_RDI+7 → R_RAX`이다. Lua 요약을 읽는 **같은 적용기**에 이 파일을 넣어 입력 `9`, `0`, `1`, `UINT64_MAX-7`, `UINT64_MAX` 5건의 반환 레지스터와 프로그램 출력을 맞췄다. 메모리 효과가 없으므로 같은 형식의 빈 효과 목록을 사용한다. 이 결과는 형식과 적용기의 작은 이식성 확인이며 Python·JavaScript·VMP 분석 성공을 뜻하지 않는다.

모든 사례, 추적 SHA-256, 요약 SHA-256, 예상값과 실제 출력은 [검증 결과 JSON](transition_summary_validation.json)에 있다. 원시 Lua 경계 추적은 `artifacts/lua_handler_plus{7,11}_*.jsonl`, 네이티브 원시 CSV와 변환 경계 추적은 `artifacts/elf_transition_*`에 보관했다. 검증 코드는 [validate_transition_summaries.py](validate_transition_summaries.py)이다.

## 재현

기존 실험의 Python 환경에서 이 디렉터리를 현재 작업 디렉터리로 두고 실행한다.

```bash
python pcode_transition_summary.py artifacts/lua_bundle.tar.gz artifacts/lua_handler_plus7_x9.jsonl lua_interpreter_fixture handler_summary_plus7.json
python build_native_transition_summary.py artifacts/elf_bundle.tar.gz artifacts/elf_trace_x9.csv elf_expression_fixture artifacts/elf_transition_x9.jsonl native_summary_add7.json
python validate_transition_summaries.py
```

Lua 추적 재수집 예시는 다음과 같다. 각 추적은 실행기 진입에서 약 5.3만 명령을 단일 단계로 지나지만 파일에는 필요한 지점과 처리 구간만 남긴다. 새 바이트코드에 **요약을 적용할 때** 이 전체 단일 단계 실행은 필요하지 않고, 처리 진입의 `W`·레지스터·메모리 snapshot만 필요하다. 이번 차등 검증에서는 실제 효과 비교를 위해 추적을 수집했다.

```bash
python trace_input_provenance.py ./lua_interpreter_fixture ./lua_chunk_plus11.luac 9 artifacts/lua_handler_plus11_x9.jsonl --limit 100000 --capture-handler --markers-only
```

## 적용 범위와 다음 단계

이 요약은 관측한 **한 정수 fast 경로의 후보**다. 여러 입력에서 일치했지만 모든 워드·메모리·별칭 관계에 대한 정적 증명은 아니다. 다른 태그/느린 경로와 예외, 초기 메모리 snapshot 범위 밖 읽기, 쓰기 이후 새 메모리 읽기, 코드 자체 수정은 아직 처리하지 않는다. 선택한 일반 레지스터와 플래그를 출력하지만 모든 상태 영역의 frame 보존을 증명하지 않았다. 또한 요약의 진입은 handler이고 종료는 다음 fetch 직전이라, 바이트코드 두 개를 연속 합성하려면 그 사이의 fetch/decode/dispatch 전이와 입력 바인딩을 먼저 연결해야 한다.

명령 위치와 VM 슬롯이 달라지는 세 번째 바이트코드의 적용과 fetch/decode/dispatch 연결 전이는 [별도 결과](TWO_HANDLER_COMPOSITION_RESULT.md)에 기록했다. Python·JavaScript용 adapter는 이 첫 관문의 경계·메모리 계약을 바탕으로 차례로 다룬다.
