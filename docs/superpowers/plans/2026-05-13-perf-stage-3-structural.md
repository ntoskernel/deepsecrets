# DeepSecrets Performance — Stage 3: Structural Improvements (schutz-safe)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Точечные «глубинные» улучшения, которые дают +10…30% к скорости, но требуют осторожности: они затрагивают модели данных, формат отчётов или семантику пропуска файлов. Каждое изменение — само себе фича, может быть включено/выключено независимо.

**Architecture:** Все правки реализованы behaviour-preserving по умолчанию (без флагов), либо с opt-in флагом для тех, что меняют состав детекций (blob-skip, encoding fallback). Pydantic-модели, которые внешние потребители (`service-secrets-schutz`) наследуют или вызывают `model_dump()` — **не трогаем**. Структурные дешевизны (`__slots__`, dict вместо OrderedSet) применяем только к внутренним хелперам.

**Tech Stack:** Python stdlib, `mmh3` (уже в зависимостях), Pygments, pydantic v2.

---

## ⚠️ Совместимость с `service-secrets-schutz`

Перед началом — **зафиксированный список границ API**, который **нельзя ломать**. Источник: `service-secrets-schutz/lib/` использует DeepSecrets через следующие точки:

### Классы, от которых наследуются:
- `deepsecrets.core.modes.iscan_mode.ScanMode` → `lib.modes.schutz_scan_mode.SchutzScanMode` (переопределяет `run()`, абстрактный `_per_file_analyzer`). **Не менять**: `__init__(config, pool_engine=None)`, атрибуты `pool_engine`, `filepaths`, `rulesets`, `path_exclusion_rules`, `config`, `file_jobs`; методы `_get_process_count_for_runner()`, `analyzer_bundle()`, `filter_false_positives()`, `prepare_for_scan()` (abstract), `_get_files_list()`.
- `deepsecrets.core.model.file.File` → `lib.model.diff_file.DiffFile` (передаёт `path`, `relative_path`, `content`, `offsets`). **Не менять**: сигнатуру `__init__(path, relative_path=None, content=None, offsets=None)`; поведение `offsets` (`Dict[linum, (start, end)]`, ключи могут быть **несплошными** — это уже учтено в Stage 2 Task 1); поля `content`, `length`, `path`, `relative_path`, `extension`, `name`; методы `get_line_number`, `get_line_contents`, `get_full_line_for_position`, `get_span_for_string`.
- `deepsecrets.core.model.finding.Finding` → `lib.domain.entities.Finding` (добавляет `scores: list[FindingScore]`). **Не менять**: это `pydantic.BaseModel`, schutz вызывает `result.model_dump()`. Поля `file, rules, detection, full_line, linum, start_pos, end_pos, reason, final_rule` обязаны остаться pydantic-полями.
- `deepsecrets.core.rulesets.ibuilder.IRulesetBuilder` → `lib.infra.clients.ruleset_builders.HashedSecretsRulesetBuilder`. **Не менять**: `rule_model`, `ruleset_name`, `rules` атрибут, `with_rules_from_file(file)`.

### Объекты, которые schutz конструирует напрямую:
- `RegexEngine(ruleset=...)`, `SemanticEngine(regex_engine)`, `HashedSecretEngine(ruleset=...)`.
- `FullContentTokenizer()`, `LexerTokenizer(deep_token_inspection=True)`.
- `FileAnalyzer(file)` → `.add_engine(engine, [tokenizer])` → `.process(threaded=False)`.
- `FindingMerger(list).merge()`, `FindingResponse.from_list(list, disable_masking=False)`.
- `HashedSecretRule(id, name, hashed_val, algorithm, token_length, confidence)` — pydantic, schutz создаёт через kwargs.
- `Config()` + `set_workdir`, `set_disable_masking`, `set_logging_level`, `set_process_count`, `set_mp_context`, `set_global_exclusion_paths`, `add_ruleset`. Атрибут `workdir_path` (присваивается напрямую в `DiffOnlyScan.__init__`).
- `HashingAlgorithm` enum.

### Что НЕ используется и где можно резать:
- `progress_bar`, `task_reporter`, `_mp_manager`, `refresh_progress_bar` — schutz не использует (переопределяет `run()`).
- Базовый `pool_wrapper` в `iscan_mode.py` — schutz определяет свой собственный.
- `attach_global_task_reporter` — не вызывается из schutz (task_reporter остаётся None).

Каждая задача ниже помечена тегом: **[safe]** — нулевой риск; **[set-preserving]** — нужен полный regress-тест schutz; **[behaviour-change]** — меняет набор детекций, нужно согласование.

---

## File Structure

- Modify: `deepsecrets/core/model/finding.py` — mmh3 fingerprint (с сохранением signature).
- Modify: `deepsecrets/core/tokenizers/lexer.py` — `dict.fromkeys` вместо `OrderedSet`.
- Modify: `deepsecrets/core/tokenizers/helpers/semantic/var_detection/detector.py` — внутренний `__slots__` для `Match` (если останется dataclass).
- Modify: `deepsecrets/core/model/file.py` — `errors='ignore'` в `_get_contents`.
- New: `deepsecrets/core/utils/blob_filter.py` — детектор blob-файлов (opt-in через Config).
- Modify: `deepsecrets/core/modes/iscan_mode.py` — интеграция blob-filter (opt-in).
- Modify: `deepsecrets/config.py` — флаг `skip_blob_files`.
- Tests: соответствующие test files + `tests/core/utils/test_blob_filter.py`.

---

## Task 1: `mmh3` для fingerprint **[safe]**

**Rationale (Обоснование).** `finding.py:53` берёт sha256 от `detection` и обрезает срез `[23:33]` — это 10 символов hex. На каждый Finding — sha256 round, что в сумме заметно при тысячах findings. `mmh3` (уже в `pyproject.toml`) даёт 64-битный хеш за единицы наносекунд, можно отформатировать в 10 hex-символов через `format(mmh3.hash64(...)[0] & 0xFFFFFFFFFF, '010x')` — те же 10 символов, та же стабильность по содержимому.

**Совместимость со schutz:** fingerprint используется только внутри `FindingApiModel.from_finding` → SARIF/JSON отчёт. Schutz **не** сравнивает fingerprint в коде (см. `folder_scanner.py:55-57` — там свой ключ `detection.start_pos.end_pos.linum`). Однако: внешние потребители JSON-отчёта могут хранить fingerprint и сравнивать. Поэтому это **set-preserving для findings, но breaking-change для fingerprint-значений** в отчёте.

**Решение:** ввести флаг `use_fast_fingerprint` в `Config`, по умолчанию `False`. Опция активируется явно через CLI/конфиг. **[set-preserving по умолчанию]**

**Files:**
- Modify: `deepsecrets/config.py`
- Modify: `deepsecrets/core/model/finding.py`
- Modify: `deepsecrets/cli.py` (добавить флаг `--fast-fingerprint`)

- [ ] **Step 1.1: Добавить тест эквивалентности (по умолчанию sha256)**

В `tests/core/model/test_finding.py` добавить:

```python
import re
from deepsecrets.core.model.finding import Finding


def test_fingerprint_default_is_sha256_slice():
    f = Finding(detection='abc123', start_pos=0, end_pos=6)
    fp = f.get_fingerprint()
    assert len(fp) == 10
    assert re.fullmatch(r'[0-9a-f]{10}', fp)


def test_fingerprint_is_deterministic():
    f1 = Finding(detection='SAME', start_pos=0, end_pos=4)
    f2 = Finding(detection='SAME', start_pos=10, end_pos=14)
    assert f1.get_fingerprint() == f2.get_fingerprint()
```

- [ ] **Step 1.2: Запустить — должны пройти на текущей реализации**

Run: `pytest tests/core/model/test_finding.py -v`
Expected: PASS.

- [ ] **Step 1.3: Добавить флаг в Config**

В `deepsecrets/config.py` добавить:

```python
class Config:
    # ... existing fields ...
    fast_fingerprint: bool = False

    def __init__(self) -> None:
        # ... existing ...
        self.fast_fingerprint = False

    def set_fast_fingerprint(self, state: bool) -> None:
        self.fast_fingerprint = state
```

- [ ] **Step 1.4: Реализовать переключение в `Finding.get_fingerprint`**

В `deepsecrets/core/model/finding.py`:

```python
from hashlib import sha256

try:
    import mmh3  # type: ignore
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False


class Finding(BaseModel):
    # ... existing fields ...

    def get_fingerprint(self) -> str:
        # Default path preserves backwards-compatible 10-char sha256 slice.
        # Opt-in fast path uses mmh3 (set via config.fast_fingerprint).
        from deepsecrets.config import config
        if _HAS_MMH3 and getattr(config, 'fast_fingerprint', False):
            h = mmh3.hash64(self.detection.encode('utf-8'))[0] & 0xFFFFFFFFFF
            return format(h, '010x')
        return sha256(self.detection.encode('utf-8')).hexdigest()[23:33]
```

- [ ] **Step 1.5: Добавить CLI-флаг**

В `deepsecrets/cli.py` рядом с другими `add_argument`:

```python
        parser.add_argument(
            '--fast-fingerprint',
            action='store_true',
            help='Use mmh3 instead of sha256 for finding fingerprints (faster, but changes fingerprint values).',
        )
```

И в `parse_arguments`:

```python
        if user_args.fast_fingerprint:
            config.set_fast_fingerprint(True)
```

- [ ] **Step 1.6: Тест на быстрый путь**

В `tests/core/model/test_finding.py`:

```python
def test_fingerprint_fast_path_when_enabled():
    from deepsecrets.config import config
    config.fast_fingerprint = True
    try:
        f = Finding(detection='abc123', start_pos=0, end_pos=6)
        fp = f.get_fingerprint()
        assert len(fp) == 10
        assert re.fullmatch(r'[0-9a-f]{10}', fp)
    finally:
        config.fast_fingerprint = False
```

- [ ] **Step 1.7: Прогон тестов**

Run: `pytest tests/core/model/test_finding.py tests/ -x`
Expected: PASS.

- [ ] **Step 1.8: Commit**

```bash
git add deepsecrets/config.py deepsecrets/core/model/finding.py deepsecrets/cli.py tests/core/model/test_finding.py
git commit -m "perf(finding): opt-in mmh3 fingerprint via --fast-fingerprint"
```

---

## Task 2: `dict.fromkeys` вместо `OrderedSet` в lexer final_cleanup **[safe]**

**Rationale (Обоснование).** `lexer.py:127-145` использует `ordered_set.OrderedSet` для сохранения порядка и поддержки `-` (set difference). Сторонний `OrderedSet` медленнее, чем встроенный `dict.fromkeys()` (вставка/перебор), особенно при больших списках токенов. Это полностью внутренняя оптимизация — на выходе тот же список Token-объектов в том же порядке.

**Совместимость со schutz:** `final_cleanup` вызывается из `LexerTokenizer.tokenize()`, схема возврата (`List[Token]`) не меняется. **[safe]**

**Files:**
- Modify: `deepsecrets/core/tokenizers/lexer.py:127-145`

- [ ] **Step 2.1: Зафиксировать вывод лексера на референсной фикстуре**

```bash
python -c "
from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

f = File(path='tests/fixtures/4.go', relative_path='tests/fixtures/4.go')
lex = LexerTokenizer(deep_token_inspection=True)
tokens = lex.tokenize(f)
for t in tokens:
    print(repr(t.content), t.span)
" > /tmp/ds_lexer_before.txt
wc -l /tmp/ds_lexer_before.txt
```

- [ ] **Step 2.2: Переписать `final_cleanup`**

В `deepsecrets/core/tokenizers/lexer.py`:

```python
    def final_cleanup(self, tokens_all: Sequence[Token], tokens_to_be_excluded: Sequence[Token]) -> List[Token]:
        excluded_ids = {id(t) for t in tokens_to_be_excluded}
        # Use dict.fromkeys to keep order while dedupe; faster than OrderedSet.
        unique = list(dict.fromkeys(tokens_all))
        final = []
        for token in unique:
            if id(token) in excluded_ids:
                continue
            if any(type in token.type for type in types_to_filter_before):  # type: ignore
                continue
            if any(type in token.type for type in types_to_filter_after):  # type: ignore
                continue
            if token.content.replace(' ', '') in empty_tokens:
                continue
            final.append(token)
        return final
```

Удалить импорт `from ordered_set import OrderedSet`, если он остался без других use-sites (проверить `deep_analyze` — там тоже OrderedSet, его пока **не трогать**).

- [ ] **Step 2.3: Сравнить результат**

```bash
python -c "
from deepsecrets.core.model.file import File
from deepsecrets.core.tokenizers.lexer import LexerTokenizer

f = File(path='tests/fixtures/4.go', relative_path='tests/fixtures/4.go')
lex = LexerTokenizer(deep_token_inspection=True)
tokens = lex.tokenize(f)
for t in tokens:
    print(repr(t.content), t.span)
" > /tmp/ds_lexer_after.txt
diff /tmp/ds_lexer_before.txt /tmp/ds_lexer_after.txt
```

Expected: пустой diff.

- [ ] **Step 2.4: Прогон**

Run: `pytest tests/ -x`
Expected: PASS.

- [ ] **Step 2.5: Commit**

```bash
git add deepsecrets/core/tokenizers/lexer.py
git commit -m "perf(lexer): replace OrderedSet with dict.fromkeys in final_cleanup"
```

---

## Task 3: Encoding fallback в `File._get_contents` **[behaviour-change]**

**Rationale (Обоснование).** Сейчас `file.py:74-79` открывает файл без указания encoding — это значит, `open` будет читать в системной локали (`utf-8` на Linux/macOS обычно, но не всегда), и на любом не-UTF-8 файле выкинет `UnicodeDecodeError`. В блоке `try/except` ошибка проглатывается → `content` остаётся пустым → файл пропускается. На репозиториях с legacy-кодом (windows-1251, latin-1, utf-16) часть файлов исчезает из анализа.

Решение: `open(path, encoding='utf-8', errors='ignore')` — мы заведомо текст, нечитаемые байты выбрасываем. Это **меняет состав анализируемых файлов** (раньше пропускали — теперь сканируем).

**Совместимость со schutz:** schutz создаёт `File(content=...)` напрямую в `DiffFile` и `SourceFileMode`, минуя `_get_contents` (передаёт уже прочитанный `content`). А `FolderScanMode._per_file_analyzer` создаёт `File(path=file, ...)` — здесь будет вызван `_get_contents`. Изменение **может расширить состав детекций** на legacy-репах. Это положительный эффект (мы перестаём терять файлы), но требует подтверждения от владельца schutz, что больше findings — это норм.

**Решение:** сделать поведение opt-in через флаг конфига `permissive_encoding`. По умолчанию **выключено** для бит-к-бит совместимости. **[set-preserving по умолчанию]**

**Files:**
- Modify: `deepsecrets/config.py`
- Modify: `deepsecrets/core/model/file.py`
- Modify: `deepsecrets/cli.py`

- [ ] **Step 3.1: Тест на текущее поведение (UTF-8 only)**

В `tests/core/model/test_file.py` добавить:

```python
import os
import tempfile


def test_non_utf8_file_skipped_by_default():
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as tmp:
        tmp.write(b'\x80secret\x81token\n')
        tmp_path = tmp.name
    try:
        f = File(path=tmp_path)
        # Default behaviour: content empty due to encoding error.
        assert f.content == '' or 'secret' not in f.content
    finally:
        os.unlink(tmp_path)


def test_non_utf8_file_readable_with_permissive_flag():
    from deepsecrets.config import config
    config.permissive_encoding = True
    try:
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.txt', delete=False) as tmp:
            tmp.write(b'\x80secret\x81token\n')
            tmp_path = tmp.name
        try:
            f = File(path=tmp_path)
            assert 'secret' in f.content
        finally:
            os.unlink(tmp_path)
    finally:
        config.permissive_encoding = False
```

- [ ] **Step 3.2: Добавить флаг в Config**

В `deepsecrets/config.py`:

```python
    permissive_encoding: bool = False

    def __init__(self) -> None:
        # ... existing ...
        self.permissive_encoding = False

    def set_permissive_encoding(self, state: bool) -> None:
        self.permissive_encoding = state
```

- [ ] **Step 3.3: Реализовать в `_get_contents`**

В `deepsecrets/core/model/file.py`:

```python
    def _get_contents(self) -> str:
        from deepsecrets.config import config
        kwargs: Dict[str, str] = {}
        if getattr(config, 'permissive_encoding', False):
            kwargs = {'encoding': 'utf-8', 'errors': 'ignore'}
        with open(self.path, **kwargs) as f:
            raw = f.read()
            if not raw:
                return raw
            if raw[-1] != '\n':
                raw += '\n'
            return raw
```

- [ ] **Step 3.4: CLI-флаг**

В `deepsecrets/cli.py`:

```python
        parser.add_argument(
            '--permissive-encoding',
            action='store_true',
            help='Read files with errors="ignore" instead of skipping on UnicodeDecodeError.',
        )
```

В `parse_arguments`:

```python
        if user_args.permissive_encoding:
            config.set_permissive_encoding(True)
```

- [ ] **Step 3.5: Прогон**

Run: `pytest tests/ -x`
Expected: PASS — все существующие тесты используют UTF-8 фикстуры; оба новых теста проходят.

- [ ] **Step 3.6: Commit**

```bash
git add deepsecrets/config.py deepsecrets/core/model/file.py deepsecrets/cli.py tests/core/model/test_file.py
git commit -m "feat(file): opt-in permissive encoding via --permissive-encoding flag"
```

---

## Task 4: Blob-skip — пропускать файлы с минифицированными/двоичными признаками **[behaviour-change, opt-in]**

**Rationale (Обоснование).** На реальных репозиториях большая часть времени уходит на анализ файлов, которые **никогда не должны** содержать секреты в человеческом смысле: минифицированные бандлы (`*.min.js`, `bundle.js`), сгенерированные миграции БД, vendor-каталоги, lock-файлы, генерируемый код. Они уже частично пропускаются через `excluded_paths.json`, но эвристика по имени файлу не покрывает всё. Эвристика по содержимому:
1. Доля непечатаемых байт в первых 4KB > 5% → пропустить.
2. Средняя длина строки в первых 4KB > 2000 chars → минифицировано → пропустить.
3. Файл > N байт без переноса строки → пропустить.

Каждый параметр настраивается. **Этот шаг меняет состав findings (часть теряем — те, что были в минифицированных файлах).** Реализуем как opt-in флаг `--skip-blob-files`.

**Совместимость со schutz:** в schutz `FolderScanMode._per_file_analyzer` сам обрабатывает файлы. Если флаг выключен по умолчанию (а это и есть `False`), поведение не меняется. Schutz сможет включить его позже своим конфигом. **[set-preserving по умолчанию]**

**Files:**
- Create: `deepsecrets/core/utils/blob_filter.py`
- Modify: `deepsecrets/config.py`
- Modify: `deepsecrets/core/modes/iscan_mode.py` (в `_get_files_list` — фильтрация)
- Modify: `deepsecrets/cli.py`
- New test: `tests/core/utils/test_blob_filter.py`

- [ ] **Step 4.1: Создать `blob_filter.py` с unit-тестами**

`deepsecrets/core/utils/blob_filter.py`:

```python
from typing import Optional


_SAMPLE_BYTES = 4096
_DEFAULT_MAX_LINE_LENGTH = 2000
_DEFAULT_BINARY_RATIO = 0.05


class BlobFilter:
    def __init__(
        self,
        max_line_length: int = _DEFAULT_MAX_LINE_LENGTH,
        binary_ratio: float = _DEFAULT_BINARY_RATIO,
        sample_bytes: int = _SAMPLE_BYTES,
    ) -> None:
        self.max_line_length = max_line_length
        self.binary_ratio = binary_ratio
        self.sample_bytes = sample_bytes

    def is_blob(self, path: str) -> bool:
        sample = self._read_sample(path)
        if sample is None:
            return False
        if not sample:
            return False
        if self._binary_share(sample) > self.binary_ratio:
            return True
        if self._max_line(sample) > self.max_line_length:
            return True
        return False

    def _read_sample(self, path: str) -> Optional[bytes]:
        try:
            with open(path, 'rb') as f:
                return f.read(self.sample_bytes)
        except OSError:
            return None

    @staticmethod
    def _binary_share(sample: bytes) -> float:
        if not sample:
            return 0.0
        printable = sum(
            1 for b in sample
            if b == 9 or b == 10 or b == 13 or 32 <= b < 127
        )
        return 1.0 - printable / len(sample)

    @staticmethod
    def _max_line(sample: bytes) -> int:
        # Length of the longest run between '\n' bytes.
        longest = 0
        current = 0
        for b in sample:
            if b == 10:
                if current > longest:
                    longest = current
                current = 0
            else:
                current += 1
        return max(longest, current)
```

`tests/core/utils/test_blob_filter.py`:

```python
import os
import tempfile

from deepsecrets.core.utils.blob_filter import BlobFilter


def _tmp(content: bytes) -> str:
    f = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    f.write(content)
    f.close()
    return f.name


def test_plain_text_is_not_blob():
    path = _tmp(b'hello = "world"\nfoo = 1\n' * 50)
    try:
        assert BlobFilter().is_blob(path) is False
    finally:
        os.unlink(path)


def test_minified_is_blob():
    long_line = b'a' * 5000
    path = _tmp(long_line)
    try:
        assert BlobFilter().is_blob(path) is True
    finally:
        os.unlink(path)


def test_binary_is_blob():
    path = _tmp(bytes(range(256)) * 4)
    try:
        assert BlobFilter().is_blob(path) is True
    finally:
        os.unlink(path)


def test_empty_is_not_blob():
    path = _tmp(b'')
    try:
        assert BlobFilter().is_blob(path) is False
    finally:
        os.unlink(path)
```

- [ ] **Step 4.2: Запустить тесты blob_filter**

Run: `pytest tests/core/utils/test_blob_filter.py -v`
Expected: PASS.

- [ ] **Step 4.3: Добавить флаг в Config**

В `deepsecrets/config.py`:

```python
    skip_blob_files: bool = False

    def __init__(self) -> None:
        # ... existing ...
        self.skip_blob_files = False

    def set_skip_blob_files(self, state: bool) -> None:
        self.skip_blob_files = state
```

- [ ] **Step 4.4: Интегрировать в `_get_files_list`**

В `deepsecrets/core/modes/iscan_mode.py` сверху:

```python
from deepsecrets.core.utils.blob_filter import BlobFilter
```

Внутри `_get_files_list` добавить фильтр:

```python
    def _get_files_list(self) -> List[str]:
        flist = []
        if not self.path_exclusion_rules:
            excl_paths_builder = ExcludedPathsBuilder()
            for path in self.config.global_exclusion_paths:
                excl_paths_builder.with_rules_from_file(path)
            self.path_exclusion_rules = excl_paths_builder.rules

        blob_filter = BlobFilter() if self.config.skip_blob_files else None

        for fpath, _, files in os.walk(get_abspath(self.config.workdir_path)):
            for filename in files:
                full_path = os.path.join(fpath, filename)
                rel_path = full_path.replace(f'{self.config.workdir_path}/', '')
                if not self._path_included(rel_path):
                    continue

                if not self._size_check(full_path):
                    console.print(
                        f'[bold yellow]:warning: {rel_path}[/bold yellow]: File size exceeds [magenta]--max-file-path[/magenta] of {self.config.max_file_size} bytes and will be [bold]skipped[/bold]'
                    )
                    continue

                if blob_filter is not None and blob_filter.is_blob(full_path):
                    continue

                flist.append(full_path)

        return flist
```

- [ ] **Step 4.5: CLI-флаг**

В `deepsecrets/cli.py`:

```python
        parser.add_argument(
            '--skip-blob-files',
            action='store_true',
            help='Skip likely blob files (minified bundles, binaries) based on content heuristics.',
        )
```

В `parse_arguments`:

```python
        if user_args.skip_blob_files:
            config.set_skip_blob_files(True)
```

- [ ] **Step 4.6: Прогон**

Run: `pytest tests/ -x`
Expected: PASS — флаг по умолчанию выключен, поведение не меняется.

- [ ] **Step 4.7: Smoke-проверка с включённым флагом на фикстурах**

```bash
deepsecrets --target-dir tests/fixtures --skip-blob-files --outfile /tmp/r.json --outformat json --process-count 2
python -c "import json; d=json.load(open('/tmp/r.json')); print(sum(len(v) for v in d.values()), 'findings')"
```

Expected: число findings либо равно baseline, либо меньше — если меньше, проверить какие именно файлы фильтр пропустил, убедиться что они blob.

- [ ] **Step 4.8: Commit**

```bash
git add deepsecrets/core/utils/blob_filter.py deepsecrets/config.py deepsecrets/core/modes/iscan_mode.py deepsecrets/cli.py tests/core/utils/test_blob_filter.py
git commit -m "feat(scan): opt-in blob file skip via --skip-blob-files"
```

---

## Task 5: `__slots__` для внутренних классов **[safe]**

**Rationale (Обоснование).** Класс `Progress` в `file_analyzer.py:22-58` и `Semantic` в `token.py:15-24` — это plain Python classes с фиксированным набором атрибутов, инстанцируются десятки тысяч раз (по одной `Semantic` на токен с обнаруженной переменной, по одному `Progress` на файл). Добавление `__slots__` экономит ~50% памяти на инстанс и ускоряет атрибутный доступ на ~10–20%. Никакого изменения интерфейса.

**Совместимость со schutz:** `Progress` и `Semantic` — внутренние, schutz их не конструирует и не наследует. **[safe]**

**Files:**
- Modify: `deepsecrets/core/utils/file_analyzer.py:22-58`
- Modify: `deepsecrets/core/model/token.py:15-24`

- [ ] **Step 5.1: Добавить `__slots__` в Progress**

```python
class Progress:
    __slots__ = ('started', 'finished', 'total_tokens', 'processed_count', 'findings')

    def __init__(self):
        self.started = False
        self.finished = False
        self.total_tokens = 0
        self.processed_count = 0
        self.findings = 0
    # ... methods unchanged ...
```

- [ ] **Step 5.2: Добавить `__slots__` в Semantic**

```python
class Semantic:
    __slots__ = ('type', 'name', 'creds_probability')

    def __init__(self, type: SemanticType, name: str, creds_probability: int = 0) -> None:
        self.type = type
        self.name = name
        self.creds_probability = creds_probability
```

- [ ] **Step 5.3: Прогон**

Run: `pytest tests/ -x`
Expected: PASS.

- [ ] **Step 5.4: Commit**

```bash
git add deepsecrets/core/utils/file_analyzer.py deepsecrets/core/model/token.py
git commit -m "perf: __slots__ for hot internal classes"
```

---

## Task 6: Кросс-репо валидация с schutz и финальный замер

**Rationale (Обоснование).** Несколько правок в Stage 3 — opt-in флаги. Нужно убедиться, что:
1. С выключенными флагами (default) — поведение совпадает с baseline.
2. С включёнными флагами — schutz всё ещё проходит свои тесты.

- [ ] **Step 6.1: Прогон с default**

Run: `pytest tests/`
Expected: PASS на baseline-наборе.

- [ ] **Step 6.2: Прогон с включёнными флагами**

```bash
DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s
deepsecrets --target-dir tests/fixtures --skip-blob-files --fast-fingerprint --permissive-encoding \
    --outfile /tmp/r_opt.json --outformat json --process-count 2
python -c "
import json
d = json.load(open('/tmp/r_opt.json'))
print(sum(len(v) for v in d.values()), 'findings (with opt-in flags)')
"
```

Expected: время ещё меньше; число findings — либо равно, либо чуть меньше (blob-skip может убрать findings из минифицированных файлов).

- [ ] **Step 6.3: Установить локальную DeepSecrets в schutz**

```bash
cd /Users/gvbabaev/project/service-secrets-schutz
pip install -e /Users/gvbabaev/project/deepsecrets
pytest tests/ -x
cd -
```

Expected: тесты schutz PASS.

- [ ] **Step 6.4: Тег**

```bash
git tag perf-stage-3-done
```

---

## Self-Review

**Spec coverage:**
- mmh3 fingerprint (opt-in) → Task 1.
- OrderedSet → dict.fromkeys → Task 2.
- Encoding fallback (opt-in) → Task 3.
- Blob-skip (opt-in) → Task 4.
- `__slots__` → Task 5.
- schutz-regress → Task 6.

**Placeholder scan:** все шаги конкретны. Меняющие поведение правки явно помечены и сделаны opt-in.

**Type consistency:** `fast_fingerprint`, `permissive_encoding`, `skip_blob_files` — bool, инициализированы в `Config.__init__`, дублированы как сеттеры `set_*`. CLI-флаги имеют единый стиль `--<flag-name>`.

**schutz-compat:** все breaking-change правки (Tasks 1, 3, 4) реализованы как opt-in с default=False; Tasks 2 и 5 не меняют внешнее поведение; Task 6 явно прогоняет тесты schutz.
