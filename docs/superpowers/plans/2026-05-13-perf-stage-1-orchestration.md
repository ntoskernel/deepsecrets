# DeepSecrets Performance — Stage 1: Orchestration & Hot-Loop IPC

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Убрать системные накладные расходы оркестрации (IPC на каждый токен, busy-loop, перепикливание бандла, двойная токенизация Pygments) без изменения функционала и API. Ожидаемое ускорение: 2–10× на больших репозиториях.

**Architecture:** Pool с initializer, чтобы рулсеты пиклились один раз. Прогресс-репортинг батчем через единый `Queue` вместо `Manager.dict()`. Главный процесс ждёт результаты через `imap_unordered`/коротким `sleep` вместо busy-loop. В лексер-токенизаторе — прямое использование `lexer.get_tokens_unprocessed()` (отдаёт смещения), вместо round-trip `highlight()` → `RawTokenFormatter()` → `RawTokenLexer().get_tokens()`. Спан токена берётся из самого Pygments, а не пересчитывается регуляркой.

**Tech Stack:** Python 3.9+, `multiprocessing` (spawn), Pygments, `regex`/`re`, pytest.

---

## File Structure

- Modify: `deepsecrets/core/utils/file_analyzer.py` — батчинг прогресса, удаление `global_report()` из горячего цикла.
- Modify: `deepsecrets/core/modes/iscan_mode.py` — переход на `Queue` + `imap_unordered`, `Pool(initializer=...)`.
- Modify: `deepsecrets/scan_modes/cli.py` — `_per_file_analyzer` читает бандл из module-global, заданного через initializer.
- Modify: `deepsecrets/core/tokenizers/lexer.py` — переход на `get_tokens_unprocessed`, удаление вызовов `file.get_span_for_string` в горячем цикле.
- Test: `tests/core/utils/test_file_analyzer.py`, `tests/scan_modes/test_cli_scan_mode.py`, `tests/generic_fixture_scans/test_run_full_scan.py` — существующие тесты выступают регрессионным гейтом.
- New test: `tests/perf/test_orchestration_smoke.py` — простой smoke-бенчмарк (запускается вручную, не падает CI).

---

## Task 1: Бенчмарк baseline

**Rationale (Обоснование).** Прежде чем оптимизировать, нужно зафиксировать текущую цифру. Без числа невозможно отличить «стало быстрее» от «кажется быстрее». Это разовая инвестиция в 5 минут, которая защищает от регрессий на каждом следующем шаге.

**Files:**
- Create: `tests/perf/__init__.py`
- Create: `tests/perf/test_orchestration_smoke.py`

- [ ] **Step 1.1: Создать пустой `__init__.py`**

```python
# tests/perf/__init__.py
```

- [ ] **Step 1.2: Написать smoke-бенчмарк**

```python
# tests/perf/test_orchestration_smoke.py
import os
import time
from unittest.mock import Mock

import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.scan_modes.cli import CliScanMode


@pytest.mark.skipif(
    os.environ.get('DEEPSECRETS_PERF') != '1',
    reason='Run with DEEPSECRETS_PERF=1 for manual benchmarking',
)
def test_baseline_fixtures_scan_duration(capsys):
    config = Config()
    config.set_workdir('tests/fixtures')
    config.set_process_count(4)
    config.engines.append(RegexEngine)
    config.engines.append(SemanticEngine)
    config.add_ruleset(RegexRulesetBuilder, ['deepsecrets/rules/regexes.json'])
    config.output = Output(type='json', path='/tmp/ds_baseline.json')

    mode = CliScanMode(config=config)
    mode.progress_bar = Mock()
    mode.progress_bar.add_task.return_value = 0

    start = time.perf_counter()
    findings = mode.run()
    elapsed = time.perf_counter() - start
    mode.dispose()

    with capsys.disabled():
        print(f'\n[BENCH] files={len(mode.filepaths)} findings={len(findings)} elapsed={elapsed:.3f}s')
```

- [ ] **Step 1.3: Запустить бенчмарк и записать baseline**

Run: `DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s`
Expected: PASS, в выводе строка `[BENCH] files=... elapsed=...s`. Записать число.

- [ ] **Step 1.4: Прогнать существующий test suite — фиксация green baseline**

Run: `pytest tests/ -x`
Expected: PASS (или зафиксировать список текущих фейлов — Stage 1 не должен их менять).

- [ ] **Step 1.5: Commit**

```bash
git add tests/perf/__init__.py tests/perf/test_orchestration_smoke.py
git commit -m "test: add manual perf smoke benchmark"
```

---

## Task 2: Заменить per-token прогресс-репортинг на батчинг

**Rationale (Обоснование).** В `file_analyzer.py:158-164` методы `on_token_processing_start/end` вызывают `global_report()` после каждого токена, который пишет в `Manager.dict()` — это IPC через socket с pickle round-trip. Для файла с десятками тысяч токенов мы делаем десятки тысяч межпроцессных вызовов из ничего: пользователь всё равно видит обновления прогресса максимум 10 раз в секунду (см. `cli.py:53` — `refresh_per_second=10`). Батчинг (репорт раз в N токенов) сохраняет визуальный прогресс, но устраняет 99%+ IPC-нагрузки.

**Files:**
- Modify: `deepsecrets/core/utils/file_analyzer.py:133-164`
- Test: `tests/core/utils/test_file_analyzer.py` (smoke-проход уже есть)

- [ ] **Step 2.1: Добавить тест, что прогресс отчитывается ≤ ceil(tokens/batch)+2 раз**

Открыть `tests/core/utils/test_file_analyzer.py` и добавить тест после существующего:

```python
def test_progress_reporter_is_batched(file_toml_1):
    file_analyzer = FileAnalyzer(file_toml_1)

    lex = LexerTokenizer(deep_token_inspection=True)
    semantic_engine = SemanticEngine(subengine=None)
    file_analyzer.add_engine(engine=semantic_engine, tokenizers=[lex])

    calls = []

    class FakeReporter(dict):
        def __setitem__(self, key, value):
            calls.append(dict(value))
            super().__setitem__(key, value)

    file_analyzer.attach_global_task_reporter(task_reporter=FakeReporter(), task_id='t1')
    file_analyzer.process()

    total_tokens = file_analyzer.progress.total_tokens
    # Up to ceil(total_tokens / 256) batched updates + start/end markers.
    assert len(calls) <= max(4, (total_tokens // 256) + 4)
```

- [ ] **Step 2.2: Запустить тест — должен упасть (репортов слишком много)**

Run: `pytest tests/core/utils/test_file_analyzer.py::test_progress_reporter_is_batched -v`
Expected: FAIL (слишком много вызовов `__setitem__`).

- [ ] **Step 2.3: Внести минимальную правку в `FileAnalyzer`**

В файле `deepsecrets/core/utils/file_analyzer.py` заменить методы:

```python
PROGRESS_BATCH_SIZE = 256


class FileAnalyzer:
    # ... existing fields ...

    def __init__(self, file: File, pool_class: Optional[Type] = None):
        if pool_class is not None:
            self.pool_class = Pool
        else:
            self.pool_class = pool_class

        self.engine_tokenizers = []
        self.file = file
        self.tokens = {}
        self.tokenizers_lock = RLock()
        self.progress = Progress()
        self.task_reporter = None
        self.task_id = None
        self._since_last_report = 0  # NEW

    def on_token_processing_start(self, token: Token):
        self.progress.on_token_processing_start()
        self._since_last_report += 1
        if self._since_last_report >= PROGRESS_BATCH_SIZE:
            self._since_last_report = 0
            self.global_report()

    def on_token_processing_end(self, findings_count: int):
        self.progress.add_findings_count(findings_count)
        # No per-token report; batched by start hook.
```

И в `_run_engine` после `self.progress.on_finish()` добавить финальный flush:

```python
        self.progress.on_finish()
        self.global_report()  # final flush per engine
        return results
```

- [ ] **Step 2.4: Прогнать новый тест и существующие**

Run: `pytest tests/core/utils/test_file_analyzer.py -v`
Expected: PASS — оба теста.

Run: `pytest tests/ -x`
Expected: то же количество PASS, что и в baseline.

- [ ] **Step 2.5: Commit**

```bash
git add deepsecrets/core/utils/file_analyzer.py tests/core/utils/test_file_analyzer.py
git commit -m "perf(file_analyzer): batch progress reports to reduce IPC overhead"
```

---

## Task 3: Убрать busy-loop в координаторе и добавить sleep

**Rationale (Обоснование).** `iscan_mode.py:132-133` крутит `while sum([job.ready() for job in self.file_jobs]) < len(self.file_jobs): self.refresh_progress_bar(...)` — главный процесс жжёт 100% CPU и одновременно читает всю Manager dict со всех воркеров на каждой итерации. После Task 2 нагрузка на dict уменьшилась, но цикл сам по себе — лишняя работа. Прогрессбар рендерится 10 раз/сек (см. `cli.py:53`), значит спать ≥100ms между обновлениями безопасно. Это типичный паттерн в multiprocessing: координатор просыпается по таймеру, а не «жрёт ядро ради цикла».

**Files:**
- Modify: `deepsecrets/core/modes/iscan_mode.py:102-138`

- [ ] **Step 3.1: Добавить sleep и преобразовать цикл ожидания**

В `deepsecrets/core/modes/iscan_mode.py` сверху добавить импорт:

```python
import time
```

Заменить блок `while ... < len(self.file_jobs):` на:

```python
                last_render = 0.0
                while True:
                    n_finished = sum(1 for job in self.file_jobs if job.ready())
                    now = time.monotonic()
                    if now - last_render >= 0.1:
                        self.refresh_progress_bar(overall_progress_task, n_finished)
                        last_render = now
                    if n_finished >= len(self.file_jobs):
                        break
                    time.sleep(0.05)
                pool.close()
```

- [ ] **Step 3.2: Проверить, что full-scan тест зелёный**

Run: `pytest tests/scan_modes/test_cli_scan_mode.py -v`
Expected: PASS.

Run: `pytest tests/generic_fixture_scans/test_run_full_scan.py -v`
Expected: PASS (если фейлится по сравнению с baseline — откат).

- [ ] **Step 3.3: Commit**

```bash
git add deepsecrets/core/modes/iscan_mode.py
git commit -m "perf(scan_mode): replace busy-loop with sleep-based coordinator"
```

---

## Task 4: Передавать бандл рулсетов один раз через `Pool(initializer=...)`

**Rationale (Обоснование).** Сейчас `pool.apply_async(pool_wrapper, (bundle, ...))` (`iscan_mode.py:126-130`) шлёт скомпилированные regex'ы и DotWiz в дочерний процесс **на каждый файл**. При 10к файлов мы пиклим один и тот же бандл 10к раз. Стандартный паттерн `multiprocessing.Pool` — это `initializer`, в котором воркер получает тяжёлые объекты один раз и кладёт их в module-level, а в задачи передаются только лёгкие аргументы (путь к файлу). Уменьшает per-task IPC до нескольких десятков байт.

**Files:**
- Modify: `deepsecrets/core/modes/iscan_mode.py:45-138, 240-244`
- Modify: `deepsecrets/scan_modes/cli.py:42-100`

- [ ] **Step 4.1: Создать модульный держатель бандла в `iscan_mode.py`**

В конце файла `deepsecrets/core/modes/iscan_mode.py` (после функции `pool_wrapper`) добавить:

```python
_WORKER_BUNDLE: Optional[DotWiz] = None


def _worker_init(bundle: DotWiz) -> None:
    global _WORKER_BUNDLE
    _WORKER_BUNDLE = bundle


def pool_wrapper(  # type: ignore[no-redef]
    runner: Callable, task_id: Optional[int], task_reporter: DictProxy, file: str
) -> List[Finding]:  # pragma: nocover
    assert _WORKER_BUNDLE is not None, 'Worker bundle was not initialized'
    return runner(_WORKER_BUNDLE, file, task_id, task_reporter)
```

Удалить старую сигнатуру `pool_wrapper(bundle, runner, ...)` — выше уже есть новая.

- [ ] **Step 4.2: Использовать initializer при создании пула**

В `ScanMode.run()` (внутри `with self.pool_engine(processes=proc_count) as pool:` блок) заменить создание пула:

```python
            with self.pool_engine(
                processes=proc_count,
                initializer=_worker_init,
                initargs=(bundle,),
            ) as pool:
                for file in self.filepaths:
                    task_id = self.progress_bar.add_task(file, findings='FINDINGS: 0', visible=False)
                    self.file_jobs.append(
                        pool.apply_async(
                            pool_wrapper,
                            (self._per_file_analyzer, task_id, self.task_reporter, file),
                        )
                    )
```

- [ ] **Step 4.3: Прогнать full-scan тест**

Run: `pytest tests/scan_modes/test_cli_scan_mode.py tests/generic_fixture_scans/ -v`
Expected: PASS, набор `detections` идентичен baseline.

- [ ] **Step 4.4: Замерить ускорение**

Run: `DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s`
Expected: PASS, число `elapsed=` меньше baseline из Task 1.

- [ ] **Step 4.5: Commit**

```bash
git add deepsecrets/core/modes/iscan_mode.py
git commit -m "perf(scan_mode): pass bundle via Pool initializer (one pickle per worker)"
```

---

## Task 5: Прямое использование `lexer.get_tokens_unprocessed` вместо round-trip

**Rationale (Обоснование).** В `lexer.py:88-89` сейчас стоит антипаттерн: `highlight(content, lexer, RawTokenFormatter())` отдаёт текстовый дамп токенов, который потом снова парсится `RawTokenLexer().get_tokens(result)`. То есть Pygments токенизирует, сериализует в текст, токенизирует текст — двойной проход. У всех Pygments-лексеров есть `get_tokens_unprocessed(content)`, который возвращает итератор `(index, ttype, value)` напрямую — это то, что было нужно изначально. Дополнительный бонус: `index` — это уже корректная позиция в исходном файле, что делает Task 6 тривиальной.

**Files:**
- Modify: `deepsecrets/core/tokenizers/lexer.py:73-121`

- [ ] **Step 5.1: Убедиться, что текущие тесты лексера зелёные**

Run: `pytest tests/core/tokenizers/ -v`
Expected: PASS (или зафиксировать какие были фейлы до правок).

- [ ] **Step 5.2: Заменить тело `tokenize`**

В `deepsecrets/core/tokenizers/lexer.py` удалить импорты `highlight`, `RawTokenFormatter`, `RawTokenLexer`. Сверху файла:

```python
from typing import List, Optional, Sequence, Set, Type, Union

from deepsecrets.core.utils.log import logger

from ordered_set import OrderedSet
from pygments.lexers.special import Lexer
from pygments.token import Token as PygmentsToken
```

Заменить тело метода `tokenize` (начиная со `result = highlight(...)`):

```python
        try:
            raw_tokens = list(self.lexer.get_tokens_unprocessed(file.content))
        except Exception as e:
            logger.exception(e)
            return self.tokens

        token_improver = SpotImprovements(lang=self.language)

        for index, ttype, content in raw_tokens:
            types: List[Type] = self._get_types_for_token(ttype)
            start = index
            end = start + len(content)

            try:
                sanitized = self.sanitize(content)
                if not sanitized:
                    continue

                # Adjust span if sanitize stripped surrounding quotes.
                if sanitized != content:
                    offset = content.find(sanitized)
                    if offset >= 0:
                        start = index + offset
                        end = start + len(sanitized)

                token = Token(file=file, content=sanitized, span=[start, end])
                token.set_type(types)

                improved_tokens = token_improver.improve_token(self.tokens, self.token_stream, token)
                self.tokens.extend(improved_tokens)
                self.add_to_token_stream(improved_tokens)
            except Exception as e:
                str(e)

        tokens_to_be_excluded = []
        if self.settings.deep_token_inspection is True:  # type: ignore
            tokens_to_be_excluded = self.deep_analyze()

        return self.final_cleanup(self.tokens, tokens_to_be_excluded) if post_filter else list(self.tokens)
```

- [ ] **Step 5.3: Прогнать тесты лексера и детекторов переменных**

Run: `pytest tests/core/tokenizers/ tests/core/model/test_token.py -v`
Expected: PASS на том же наборе, что был зелёным до правки.

- [ ] **Step 5.4: Полный регрессионный прогон**

Run: `pytest tests/ -x`
Expected: PASS на том же наборе. Список `detections` в full-scan тесте идентичен baseline.

- [ ] **Step 5.5: Замерить ускорение**

Run: `DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s`
Expected: `elapsed=` меньше предыдущего шага.

- [ ] **Step 5.6: Commit**

```bash
git add deepsecrets/core/tokenizers/lexer.py
git commit -m "perf(lexer): use get_tokens_unprocessed instead of highlight+RawTokenLexer roundtrip"
```

---

## Task 6: Убрать `get_span_for_string` из горячего пути и из `SpotImprovements`

**Rationale (Обоснование).** В `file.py:108-120` `get_span_for_string` делает `re.escape(s)` + `re.finditer` по подстроке файла. Это вызывается в двух местах горячего пути:
1. В оригинальном `LexerTokenizer.tokenize` — после Task 5 уже не нужно, потому что `get_tokens_unprocessed` отдаёт позицию.
2. В `SpotImprovements._curl_argstring_breakdown` (`spot_improvements.py:53`) — для каждой части после `split(':')`. Здесь позиция тоже легко вычисляется из исходного спана и длин частей.

`get_span_for_string` сам метод оставляем (используется в тестах и в `regex`-движке-неявных местах — проверяем grep). Но из горячих циклов выкидываем.

**Files:**
- Modify: `deepsecrets/core/tokenizers/helpers/spot_improvements.py:44-58`

- [ ] **Step 6.1: Найти все use-sites `get_span_for_string`**

Run: `grep -rn 'get_span_for_string' deepsecrets/ tests/`
Expected: использования в `lexer.py` (после Task 5 — отсутствует), `spot_improvements.py:53`, тесты в `tests/core/model/test_file.py`.

- [ ] **Step 6.2: Переписать `_curl_argstring_breakdown` без `get_span_for_string`**

В `deepsecrets/core/tokenizers/helpers/spot_improvements.py` заменить хвост функции:

```python
        new_parts = current_token.content.split(':')
        if new_parts[0] == '' or new_parts[1] == '':
            return [current_token]

        final = []
        cursor = current_token.span[0]
        for i, part in enumerate(new_parts):
            t = Token(
                file=current_token.file,
                content=part,
                span=[cursor, cursor + len(part)],
            )
            t.set_type([PygmentsToken.Text])
            final.append(t)
            cursor += len(part) + 1  # +1 for ':' separator
        return final
```

- [ ] **Step 6.3: Прогнать тест Shell-детекции переменных**

Run: `pytest tests/core/tokenizers/lexer/variable_detection/test_sh.py -v`
Expected: PASS.

- [ ] **Step 6.4: Полный прогон**

Run: `pytest tests/ -x`
Expected: PASS на том же наборе.

- [ ] **Step 6.5: Commit**

```bash
git add deepsecrets/core/tokenizers/helpers/spot_improvements.py
git commit -m "perf(tokenizer): compute split spans by cursor instead of regex search"
```

---

## Task 7: Финальный замер и зафиксировать новый baseline

**Rationale (Обоснование).** После пяти точечных правок нужно одной цифрой подтвердить совокупный эффект и зафиксировать новую границу для следующих этапов. Если speed-up меньше ожидаемого — это сигнал, что один из шагов не сработал и стоит инвестигировать.

- [ ] **Step 7.1: Прогнать smoke-бенчмарк**

Run: `DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s`
Expected: `[BENCH] ... elapsed=X.XXXs` с X меньше Task 1 baseline (ожидаем минимум 2×).

- [ ] **Step 7.2: Полный регресс**

Run: `pytest tests/`
Expected: количество PASS равно baseline из Task 1 Step 4.

- [ ] **Step 7.3: Прогнать тяжёлый ручной бенчмарк (опционально)**

Если есть локальный большой репозиторий (например, склонированный `cpython` или `kubernetes`):

Run: `time deepsecrets --target-dir <path> --outfile /tmp/r.json --outformat json --process-count 4`
Expected: время существенно меньше доSt1.

- [ ] **Step 7.4: Тег коммита**

```bash
git tag perf-stage-1-done
```

---

## Self-Review

**Spec coverage:**
- IPC на каждый токен → Task 2.
- Busy-loop → Task 3.
- Pickling бандла на файл → Task 4.
- Pygments round-trip → Task 5.
- `get_span_for_string` в горячем цикле → Task 5 + Task 6.
- Baseline-замеры → Task 1 + Task 7.

**Placeholder scan:** обоснования и код-сниппеты содержат конкретику; нет «TBD», «handle edge cases», «similar to».

**Type consistency:** `_WORKER_BUNDLE`, `_worker_init`, новый `pool_wrapper` согласованы между Task 4 шагами; имена методов `on_token_processing_start/end` остаются прежними (Task 2).
