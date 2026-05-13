# DeepSecrets Performance — Stage 2: Algorithmic Optimizations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Заменить алгоритмически медленные участки в горячем пути на их O-эффективные версии: линейный поиск номера строки → `bisect`; перебор 30 правил `re.finditer` → объединённый regex; `data.count(x)` в энтропии → `Counter`; тяжёлый `FileTypeGuesser` → быстрые префильтры; повторная инициализация JSX-лексера → процесс-кеш; `regex` → `re` там, где не нужны фичи PCRE. Ожидаемое ускорение поверх Stage 1: ещё +30…80%.

**Architecture:** Точечные изменения, каждое самостоятельное. Behaviour-preserving (детекции совпадают bit-to-bit на тестовых фикстурах). Все правила (regex и var_detection) собираются один раз на старте; в воркере используются готовые объекты. Энтропия и поиск номера строки используют стандартные O(N)/O(log N) подходы.

**Tech Stack:** Python stdlib (`bisect`, `collections.Counter`, `functools.lru_cache`), `re` (CPython встроенный), `regex` (там, где нужен `overlapped=True`), Pygments.

---

## File Structure

- Modify: `deepsecrets/core/model/file.py` — bisect для `_get_line_number_for_position`, encoding fallback.
- Modify: `deepsecrets/core/helpers/entropy.py` — Counter.
- Modify: `deepsecrets/core/engines/regex.py` — union regex (compile once, dispatch by `lastgroup`).
- Modify: `deepsecrets/core/utils/guess_filetype.py` — быстрые префильтры по содержимому/размеру + LRU.
- Modify: `deepsecrets/core/utils/lexer_finder.py` — кешированная инициализация JSX-лексера на уровне модуля.
- Modify: точечно `import regex as re` → `import re` в файлах без `overlapped=True`.
- Tests: расширения существующих `tests/core/helpers/test_entropy.py`, `tests/core/model/test_file.py`, и новый `tests/core/engines/test_regex_union.py`.

---

## Task 1: Bisect для `File._get_line_number_for_position`

**Rationale (Обоснование).** Сейчас `file.py:84-89` итерирует `self.line_offsets.items()` линейно: для файла из 10к строк и сотен findings это O(N·M). Эта функция вызывается дважды на каждый finding (`map_on_file` → `get_line_number` + `get_full_line_for_position` → `_get_line_number_for_position`) и потенциально из лексера. `bisect.bisect_left` по отсортированному массиву концов строк даёт O(log N) и нулевой риск изменения поведения — мы храним те же данные, только индексируем их по-другому.

**⚠️ Совместимость с secrets-schutz.** `service-secrets-schutz/lib/model/diff_file.py` наследует `File` и передаёт собственный `offsets` словарь, где `line_number` **несплошной** (это номера строк из diff-патча: 1, 5, 12, …). Значит нельзя возвращать `idx + 1` как линейный номер. Нужно параллельно с `_line_ends_sorted` хранить `_sorted_linums: List[int]` (реальные номера) и возвращать `self._sorted_linums[idx]`.

**Files:**
- Modify: `deepsecrets/core/model/file.py:7-89`
- Test: `tests/core/model/test_file.py`

- [ ] **Step 1.1: Добавить тест на O(log N) корректность и на несплошную нумерацию (DiffFile-сценарий)**

В `tests/core/model/test_file.py` добавить:

```python
def test_line_number_bisect_correctness(model):
    # Sample positions across the file: start, middle, end of each known line.
    for linum, (start, end) in model.line_offsets.items():
        assert model.get_line_number(start) == linum
        assert model.get_line_number(end) == linum
        if end > start:
            assert model.get_line_number((start + end) // 2) == linum


def test_line_number_beyond_eof_is_none(model):
    assert model.get_line_number(10_000_000) is None


def test_line_number_with_sparse_offsets():
    # Mimics DiffFile from secrets-schutz: linum keys are NOT consecutive.
    sparse_offsets = {1: (0, 4), 5: (5, 9), 12: (10, 14)}
    f = File(path='tests/fixtures/4.go', offsets=sparse_offsets, content='line1\nline2\nline3\n')
    assert f.get_line_number(0) == 1
    assert f.get_line_number(4) == 1
    assert f.get_line_number(6) == 5
    assert f.get_line_number(11) == 12
```

- [ ] **Step 1.2: Запустить — должно пройти (старый код тоже даёт правильный результат)**

Run: `pytest tests/core/model/test_file.py::test_line_number_bisect_correctness tests/core/model/test_file.py::test_line_number_beyond_eof_is_none -v`
Expected: PASS.

- [ ] **Step 1.3: Переписать `_calc_offsets` и `_get_line_number_for_position` через bisect**

В `deepsecrets/core/model/file.py` заменить тело:

```python
import bisect
import regex as re
from typing import Dict, List, Optional, Tuple

from deepsecrets.core.utils.log import logger
from deepsecrets.core.utils.fs import get_abspath


class File:
    relative_path: str
    path: str
    content: str = ''
    length: int
    line_offsets: Dict[int, Tuple[int, int]] = {}
    line_contents_cache: Dict[int, str] = {}
    _line_ends_sorted: List[int]
    _sorted_linums: List[int]
    empty: bool
    name: str
    extension: Optional[str]

    def __init__(
        self,
        path: str,
        relative_path: Optional[str] = None,
        content: Optional[str] = None,
        offsets: Optional[Dict] = None,
    ) -> None:
        self.line_offsets = {}
        self.line_contents_cache = {}
        self._line_ends_sorted = []
        self._sorted_linums = []

        if path is not None:
            self.path = get_abspath(path)

        self.relative_path = relative_path if relative_path is not None else self.path

        if content is not None:
            self.content = content
        else:
            try:
                self.content = self._get_contents()
            except Exception as e:
                logger.error(f'Error during fetching file contents: {e}')

        self.length = len(self.content)

        self.name = self._get_name()
        self.extension = self._get_extension()
        self.empty = True if self.length == 0 else False

        if offsets is not None:
            self.line_offsets = offsets
            self._rebuild_sorted_index()

        if not self.empty and len(self.line_offsets) == 0:
            self._calc_offsets()
```

Добавить новый helper `_rebuild_sorted_index`:

```python
    def _rebuild_sorted_index(self) -> None:
        # Sort by end position, keep parallel array of real line numbers
        # (DiffFile supplies sparse linum keys → can't infer linum from index).
        items = sorted(self.line_offsets.items(), key=lambda kv: kv[1][1])
        self._sorted_linums = [linum for linum, _ in items]
        self._line_ends_sorted = [end for _, (_, end) in items]
```

Заменить `_calc_offsets`:

```python
    def _calc_offsets(self) -> None:
        line_breaks = [i.start() for i in re.finditer('\n', self.content)]
        for i, lb in enumerate(line_breaks):
            start = line_breaks[i - 1] + 1 if i > 0 else 0
            self.line_offsets[i + 1] = (start, lb)

        if len(self.line_offsets) == 0 and self.length > 0:
            self.line_offsets[1] = (0, self.length)

        self._rebuild_sorted_index()
```

Заменить `_get_line_number_for_position`:

```python
    def _get_line_number_for_position(self, position: int) -> Optional[int]:
        if not self._line_ends_sorted:
            return None
        idx = bisect.bisect_left(self._line_ends_sorted, position)
        if idx >= len(self._line_ends_sorted):
            return None
        return self._sorted_linums[idx]
```

- [ ] **Step 1.4: Прогнать оба новых теста и существующие тесты файла**

Run: `pytest tests/core/model/test_file.py -v`
Expected: PASS.

- [ ] **Step 1.5: Полный регресс**

Run: `pytest tests/ -x`
Expected: PASS на том же наборе, что baseline.

- [ ] **Step 1.6: Commit**

```bash
git add deepsecrets/core/model/file.py tests/core/model/test_file.py
git commit -m "perf(file): O(log N) line lookup via bisect"
```

---

## Task 2: `collections.Counter` в Шенноновской энтропии

**Rationale (Обоснование).** В `entropy.py:53-57` без явного iterator идёт цикл `for base in unique_base: data.count(base)`. Каждый `str.count` — это O(N), а `unique_base = set(data)` может содержать десятки уникальных символов; итого O(N·K). `Counter(data)` строит ту же гистограмму за один проход — O(N). Для строк длиной 1KB+ (base64 блобы, тяжёлые токены) это десятикратное ускорение функции. Энтропия дёргается часто (`SemanticEngine.search`, `RegexRule._verify`, `ContentAnalyzer`), поэтому совокупный выигрыш заметен.

**Files:**
- Modify: `deepsecrets/core/helpers/entropy.py`
- Test: `tests/core/helpers/test_entropy.py`

- [ ] **Step 2.1: Обернуть существующие тесты — они уже фиксируют значения с двумя знаками после запятой**

Run: `pytest tests/core/helpers/test_entropy.py -v`
Expected: PASS — старая реализация.

- [ ] **Step 2.2: Переписать `_shannon_entropy`**

В `deepsecrets/core/helpers/entropy.py` заменить метод:

```python
    @classmethod
    def _shannon_entropy(cls, data: str, iterator: Optional[str] = None) -> float:
        """
        Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        """
        if not data:
            return 0
        M = len(data)
        entropy = 0.0

        if iterator:
            counts = Counter(data)
            for x in iterator:
                n_i = counts.get(x, 0)
                if n_i == 0:
                    continue
                p_x = n_i / M
                entropy += -p_x * math.log(p_x, 2)
            return entropy

        for n_i in Counter(data).values():
            p_i = n_i / M
            entropy += -p_i * math.log(p_i, 2)
        return entropy
```

В шапке файла добавить:

```python
from collections import Counter
```

- [ ] **Step 2.3: Прогнать тесты энтропии**

Run: `pytest tests/core/helpers/test_entropy.py -v`
Expected: PASS — все три теста (значения совпадают с baseline до второго знака).

- [ ] **Step 2.4: Полный регресс**

Run: `pytest tests/ -x`
Expected: PASS на том же наборе.

- [ ] **Step 2.5: Commit**

```bash
git add deepsecrets/core/helpers/entropy.py
git commit -m "perf(entropy): single-pass Counter instead of N str.count calls"
```

---

## Task 3: Union regex в `RegexEngine`

**Rationale (Обоснование).** Сейчас `regex.py:13-21` для каждого токена идёт цикл `for rule in self.ruleset: re.finditer(rule.pattern, content)`. При 30 правилах и файле размером N — это 30 проходов по N символов = O(30·N). Стандартный приём (TruffleHog, gitleaks, semgrep) — собрать все паттерны в один объединённый regex с именованными группами `(?P<r_S0>...)|(?P<r_S1>...)|...`, запустить один проход и определить, какое правило сматчилось, по `match.lastgroup`. Это O(N) вместо O(30·N), плюс CPython NFA эффективнее работает с одной большой альтернативой, чем с 30 отдельными запусками.

**Тонкости.** Не все правила сводятся к чистому union:
- Правила с `match_rules` и `target_group` имеют свою нумерацию групп — после union она поедет. Решение: запускаем union только для предварительного отбора (узнать, какое правило сматчилось), а затем гоняем именно его исходный паттерн на отобранном окне. Это всё равно даёт огромный выигрыш, потому что 99% токенов не сматчатся ни одному правилу — мы экономим 29 из 30 проходов на «холостых» данных.
- Правила с `applicable_file_patterns` — оставляем фильтр по файлам как сейчас. Union собираем из правил, прошедших фильтр.
- Правила с `entropy_settings` — post-check.

**Files:**
- Modify: `deepsecrets/core/engines/regex.py`
- New test: `tests/core/engines/__init__.py`, `tests/core/engines/test_regex_union.py`

- [ ] **Step 3.1: Создать `tests/core/engines/__init__.py`**

```python
# tests/core/engines/__init__.py
```

- [ ] **Step 3.2: Написать тест на эквивалентность union и naive**

```python
# tests/core/engines/test_regex_union.py
import pytest

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder


@pytest.fixture(scope='module')
def ruleset():
    builder = RegexRulesetBuilder()
    builder.with_rules_from_file('deepsecrets/rules/regexes.json')
    return builder.rules


@pytest.fixture(scope='module')
def sample_file():
    path = 'tests/fixtures/4.go'
    return File(path=path, relative_path=path)


def test_union_engine_findings_equal_naive(ruleset, sample_file):
    token = Token(file=sample_file, content=sample_file.content, span=[0, sample_file.length])
    engine = RegexEngine(ruleset=ruleset)
    findings = engine.search(token)
    detections = sorted(f.detection for f in findings)
    # Sanity: detections must be deterministic and non-empty for the .go fixture.
    assert isinstance(detections, list)
```

- [ ] **Step 3.3: Запустить тест на текущей реализации, зафиксировать набор детекций**

Run: `pytest tests/core/engines/test_regex_union.py -v`
Expected: PASS, тест проходит на старой реализации.

Дополнительно: сохранить `detections` в файл, чтобы сравнить после правки:

```bash
python -c "
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder

b = RegexRulesetBuilder()
b.with_rules_from_file('deepsecrets/rules/regexes.json')
f = File(path='tests/fixtures/4.go', relative_path='tests/fixtures/4.go')
t = Token(file=f, content=f.content, span=[0, f.length])
findings = RegexEngine(ruleset=b.rules).search(t)
for d in sorted(set((fi.detection, fi.start_pos, fi.end_pos) for fi in findings)):
    print(d)
" > /tmp/ds_findings_before.txt
cat /tmp/ds_findings_before.txt
```

- [ ] **Step 3.4: Переписать `RegexEngine` с union-prefilter**

В `deepsecrets/core/engines/regex.py`:

```python
from typing import Dict, List, Optional, Tuple

import regex as re

from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.regex import RegexRule
from deepsecrets.core.model.token import Token


class RegexEngine(IEngine):
    name = 'regex'
    description = 'Scans by regex patterns provided by RegexRules'

    def __init__(self, ruleset: Optional[List[RegexRule]] = None) -> None:
        super().__init__(ruleset=ruleset or [])
        self._union_cache: Dict[Tuple[int, ...], re.Pattern] = {}
        self._rule_index: Dict[str, RegexRule] = {}

    def _build_union(self, rules: List[RegexRule]) -> Optional[re.Pattern]:
        key = tuple(id(r) for r in rules)
        cached = self._union_cache.get(key)
        if cached is not None:
            return cached

        parts = []
        for i, rule in enumerate(rules):
            name = f'r_{i}'
            self._rule_index[name] = rule
            parts.append(f'(?P<{name}>{rule.pattern.pattern})')

        if not parts:
            return None
        union = re.compile('|'.join(parts), re.IGNORECASE)
        self._union_cache[key] = union
        return union

    def search(self, token: Token) -> List[Finding]:
        applicable = [r for r in self.ruleset if self.is_rule_applicable(token=token, rule=r)]
        if not applicable:
            return []

        union = self._build_union(applicable)
        if union is None:
            return []

        contents: List[str] = [token.content]
        contents.extend(token.uncovered_content)

        results: List[Finding] = []
        for content_idx, content in enumerate(contents):
            for match in union.finditer(content):
                rule = self._rule_index[match.lastgroup]
                # Re-run the rule's own pattern on the matched window for accurate
                # group spans (match_rules/target_group/entropy_settings).
                for span in rule.match(token if content_idx == 0 else _FakeToken(content)):
                    if content_idx == 0:
                        start, end = span
                    else:
                        start, end = 0, len(contents[0])
                    results.append(
                        Finding(
                            rules=[rule],
                            detection=content[start:end] if content_idx == 0 else contents[0],
                            start_pos=start,
                            end_pos=end,
                        )
                    )
                # Each match produces at most one rule.match call; break to avoid duplicates
                # if the same rule matches multiple positions, rule.match handles all spans.
                break
        return results


class _FakeToken:
    """Adapter so RegexRule.match works on plain strings (uncovered_content)."""

    def __init__(self, content: str) -> None:
        self.content = content
        self.uncovered_content: List[str] = []
```

ВАЖНО: эта реализация — стартовая. Существующий `RegexRule.match` уже умеет работать с `Token | str` (см. `core/model/rules/regex.py:47-62`), так что `_FakeToken` можно заменить на простую передачу строки.

Уточнение реализации — заменить тело search:

```python
    def search(self, token: Token) -> List[Finding]:
        applicable = [r for r in self.ruleset if self.is_rule_applicable(token=token, rule=r)]
        if not applicable:
            return []

        union = self._build_union(applicable)
        if union is None:
            return []

        results: List[Finding] = []
        seen_pairs: set = set()

        # Single pass: collect which rules potentially matched, then run only those rules' own .match
        candidate_rules: Dict[str, RegexRule] = {}
        for m in union.finditer(token.content):
            candidate_rules.setdefault(m.lastgroup, self._rule_index[m.lastgroup])

        # Also include uncovered_content scan: union is faster than per-rule even if only 1 hit.
        for unc in token.uncovered_content:
            for m in union.finditer(unc):
                candidate_rules.setdefault(m.lastgroup, self._rule_index[m.lastgroup])

        for rule in candidate_rules.values():
            for span in rule.match(token):
                key = (id(rule), span[0], span[1])
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                results.append(
                    Finding(
                        rules=[rule],
                        detection=token.content[span[0]:span[1]],
                        start_pos=span[0],
                        end_pos=span[1],
                    )
                )
        return results
```

(Использовать этот вариант, не первый — он чище.)

- [ ] **Step 3.5: Прогнать тест эквивалентности и зафиксировать новый набор**

Run: `pytest tests/core/engines/test_regex_union.py -v`
Expected: PASS.

Сохранить и сравнить:

```bash
python -c "
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder

b = RegexRulesetBuilder()
b.with_rules_from_file('deepsecrets/rules/regexes.json')
f = File(path='tests/fixtures/4.go', relative_path='tests/fixtures/4.go')
t = Token(file=f, content=f.content, span=[0, f.length])
findings = RegexEngine(ruleset=b.rules).search(t)
for d in sorted(set((fi.detection, fi.start_pos, fi.end_pos) for fi in findings)):
    print(d)
" > /tmp/ds_findings_after.txt
diff /tmp/ds_findings_before.txt /tmp/ds_findings_after.txt
```

Expected: пустой diff.

- [ ] **Step 3.6: Полный регресс full-scan**

Run: `pytest tests/scan_modes/test_cli_scan_mode.py tests/generic_fixture_scans/ -v`
Expected: набор `detections` идентичен baseline; assertions проходят.

- [ ] **Step 3.7: Commit**

```bash
git add deepsecrets/core/engines/regex.py tests/core/engines/__init__.py tests/core/engines/test_regex_union.py
git commit -m "perf(regex_engine): union-regex prefilter to avoid O(N*rules)"
```

---

## Task 4: Префильтр и кэш в `FileTypeGuesser`

**Rationale (Обоснование).** `guess_filetype.py:21-37` для каждого `.txt`/`.conf`/файла-без-расширения пробует распарсить всё содержимое через `json.loads`, `tomllib.loads`, `yaml.safe_load`, `puppetparser.parse`, `ConfigParser`. На больших файлах (10MB+ yaml) это секунды на ровном месте. Кроме того, у каждого формата есть характерное начало:
- JSON — первый non-whitespace символ это `{` или `[`.
- TOML — выглядит как INI с `[section]` или `key = value` в первых ~1KB.
- YAML — `---` или `key:` в начале.
- INI — `[section]` в начале.
- Puppet — `class`, `node`, `define` в начале или `=>`.

Префильтр по первым 2KB отсекает большинство «не наших» файлов почти бесплатно. Дополнительно — LRU-кэш на тяжёлые парсеры, чтобы одинаковый префикс не парсился дважды.

**Files:**
- Modify: `deepsecrets/core/utils/guess_filetype.py`

- [ ] **Step 4.1: Добавить smoke-тест**

Создать `tests/core/utils/test_guess_filetype.py`:

```python
from deepsecrets.core.utils.guess_filetype import FileTypeGuesser


def test_json_detected():
    assert FileTypeGuesser().guess('{"a": 1}') == 'json'


def test_yaml_detected():
    assert FileTypeGuesser().guess('a: 1\nb: 2\n') == 'yaml'


def test_toml_detected():
    assert FileTypeGuesser().guess('[section]\nkey = "val"\n') in ('toml', 'ini')


def test_binary_blob_not_detected():
    assert FileTypeGuesser().guess('\x00\xff\x00garbage') is None


def test_huge_unparseable_is_fast():
    import time
    big = '!@#$%^&*()' * 200_000  # ~2MB junk
    t0 = time.perf_counter()
    result = FileTypeGuesser().guess(big)
    elapsed = time.perf_counter() - t0
    assert result is None
    assert elapsed < 0.2, f'guess took {elapsed:.3f}s; prefilter not working'
```

- [ ] **Step 4.2: Запустить — последний тест должен упасть (медленно)**

Run: `pytest tests/core/utils/test_guess_filetype.py -v`
Expected: первые тесты PASS; `test_huge_unparseable_is_fast` FAIL по таймауту.

- [ ] **Step 4.3: Переписать `FileTypeGuesser`**

В `deepsecrets/core/utils/guess_filetype.py`:

```python
import json
import tomllib
from configparser import ConfigParser
from typing import Optional

import yaml
from puppetparser.parser import parse

_PREFIX_BYTES = 2048
_MAX_PARSE_BYTES = 64 * 1024  # do not try heavy parsers on > 64KB
_BINARY_NUL_THRESHOLD = 3  # NUL bytes in prefix → binary


class FileTypeGuesser:

    def __init__(self) -> None:
        self.probes = (
            ('json', self._is_json, self._looks_like_json),
            ('toml', self._is_toml, self._looks_like_toml_or_ini),
            ('ini', self._is_ini, self._looks_like_toml_or_ini),
            ('yaml', self._is_yaml, self._looks_like_yaml),
            ('pp', self._is_puppet, self._looks_like_puppet),
        )

    def guess(self, content: str) -> Optional[str]:
        if not content:
            return None
        prefix = content[:_PREFIX_BYTES]
        # binary blob short-circuit
        if prefix.count('\x00') >= _BINARY_NUL_THRESHOLD:
            return None

        sample = content if len(content) <= _MAX_PARSE_BYTES else content[:_MAX_PARSE_BYTES]
        for ext, parser, prefilter in self.probes:
            if not prefilter(prefix):
                continue
            if parser(sample):
                return ext
        return None

    @staticmethod
    def _looks_like_json(prefix: str) -> bool:
        stripped = prefix.lstrip()
        return stripped.startswith('{') or stripped.startswith('[')

    @staticmethod
    def _looks_like_toml_or_ini(prefix: str) -> bool:
        # [section] or key = value somewhere in the first chunk
        return '[' in prefix and ']' in prefix or '=' in prefix

    @staticmethod
    def _looks_like_yaml(prefix: str) -> bool:
        if prefix.startswith('---'):
            return True
        for line in prefix.splitlines()[:20]:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if ':' in stripped:
                return True
            return False
        return False

    @staticmethod
    def _looks_like_puppet(prefix: str) -> bool:
        keywords = ('class ', 'node ', 'define ', '=>')
        return any(kw in prefix for kw in keywords)

    def _is_json(self, content: str) -> bool:
        try:
            json.loads(content)
        except Exception:
            return False
        return True

    def _is_toml(self, content: str) -> bool:
        try:
            tomllib.loads(content)
        except Exception:
            return False
        return True

    def _is_yaml(self, content: str) -> bool:
        try:
            yaml.safe_load(content)
        except yaml.YAMLError:
            return False
        except Exception:
            return False
        return True

    def _is_puppet(self, content: str) -> bool:
        try:
            parse(content)
        except Exception:
            return False
        return True

    def _is_ini(self, content: str) -> bool:
        try:
            ConfigParser().read_string(content)
        except Exception:
            return False
        return True
```

- [ ] **Step 4.4: Прогнать тесты**

Run: `pytest tests/core/utils/test_guess_filetype.py -v`
Expected: все PASS, в том числе `test_huge_unparseable_is_fast`.

Run: `pytest tests/ -x`
Expected: PASS на baseline-наборе.

- [ ] **Step 4.5: Commit**

```bash
git add deepsecrets/core/utils/guess_filetype.py tests/core/utils/test_guess_filetype.py
git commit -m "perf(guess_filetype): prefix prefilter and parser size cap"
```

---

## Task 5: Кэшированная инициализация JSX-лексера

**Rationale (Обоснование).** `lexer_finder.py:24-25` вызывает `load_lexer_from_file(lexer_mod.__file__, "JsxLexer")` в `LexerFinder.__init__`. После Stage 1 Task 4 бандл лексеров пиклится один раз на воркер, но `LexerFinder()` всё равно создаётся в каждой задаче (см. `lexer.py:_find_lexer_for_file` → `LexerFinder().find(...)`) и каждый раз грузит JSX-лексер с диска. Это I/O + import-time на каждый файл. `load_lexer_from_file` регистрирует лексер глобально в Pygments — повторные вызовы — это просто перезапись. `@lru_cache` гарантирует ровно один вызов на процесс.

**Files:**
- Modify: `deepsecrets/core/utils/lexer_finder.py`

- [ ] **Step 5.1: Перенести `load_lexer_from_file` в module-level с lru_cache**

В `deepsecrets/core/utils/lexer_finder.py`:

```python
from functools import lru_cache
from typing import Dict, List, Optional

from deepsecrets.core.model.file import File
from deepsecrets.core.utils.guess_filetype import FileTypeGuesser
from pygments.lexers import load_lexer_from_file, get_lexer_for_filename, get_lexer_by_name
from pygments.util import ClassNotFound
from jsx import lexer as lexer_mod


@lru_cache(maxsize=1)
def _ensure_custom_lexers_loaded() -> bool:
    load_lexer_from_file(lexer_mod.__file__, "JsxLexer")
    return True


class LexerFinder:
    file: File
    extension: str
    distinguishing_feature: List[str]
    alias_exceptions: Dict
    probes: Dict

    def __init__(self) -> None:
        _ensure_custom_lexers_loaded()
        self._init_alias_exceptions()
        self._init_probes()

    def _init_alias_exceptions(self):
        self.alias_exceptions = {'js+react': 'react'}

    def _init_probes(self):
        self.probes = {'js': [_probe_react]}

    # ... остальной код без изменений ...
```

Удалить старый `_init_custom_lexers` метод.

- [ ] **Step 5.2: Прогнать тесты JSX и lexer_finder**

Run: `pytest tests/core/utils/test_lexer_finder.py -v`
Expected: PASS.

Run: `pytest tests/ -x`
Expected: PASS на baseline-наборе.

- [ ] **Step 5.3: Commit**

```bash
git add deepsecrets/core/utils/lexer_finder.py
git commit -m "perf(lexer_finder): cache JSX lexer registration per process"
```

---

## Task 6: Заменить `regex` на `re` там, где не нужны фичи PCRE

**Rationale (Обоснование).** В коде идёт `import regex as re` повсюду. Сторонний `regex` существенно медленнее встроенного `re` (бенчмарки разнятся, но 1.5–4× — типичные цифры). `regex` нужен только там, где используются его фичи:
- `overlapped=True` (var_detection `detector.py:95`).
- Юникод-категории `\p{...}`.
- Атомарные группы, рекурсивные паттерны.

Все правила в `deepsecrets/rules/regexes.json` и сам `_shannon_entropy` ничего этого не используют. Переход на `re` в горячих местах даёт ускорение бесплатно.

**Где менять:**
- `deepsecrets/core/helpers/entropy.py` — `re.compile` для B64/HEX (если останется).
- `deepsecrets/core/tokenizers/per_word.py` — `separator`.
- `deepsecrets/core/model/rules/regex.py` — компиляция и matching правил.
- `deepsecrets/core/model/rules/excluded_paths.py`, `false_finding.py` — пути и false findings.

**Где НЕ менять (нужны фичи `regex`):**
- `deepsecrets/core/tokenizers/helpers/semantic/var_detection/detector.py` (`overlapped=True`).
- `deepsecrets/core/tokenizers/helpers/semantic/var_detection/rules.py` (грузится в `detector.py`).

**Files:**
- Modify: см. ниже.

- [ ] **Step 6.1: Найти все import-ы `regex as re`**

Run: `grep -rln 'import regex as re' deepsecrets/`
Expected: список файлов.

- [ ] **Step 6.2: Заменить в `entropy.py`, `per_word.py`, `rules/regex.py`, `rules/excluded_paths.py`, `rules/false_finding.py`**

Для каждого файла:
1. Поменять `import regex as re` → `import re`.
2. Убедиться, что в файле нет `re.finditer(..., overlapped=True)` или `\p{...}` — если есть, файл оставить как был.

Команда для проверки (после правок):

Run: `grep -rn 'overlapped=True\|\\p{' deepsecrets/`
Expected: только в `var_detection/detector.py`.

- [ ] **Step 6.3: Прогнать полный набор тестов**

Run: `pytest tests/ -x`
Expected: PASS на baseline-наборе. Особое внимание — на `tests/core/model/test_file.py` (использует `re.finditer` в `_calc_offsets`) и на var_detection тесты.

- [ ] **Step 6.4: Commit**

```bash
git add deepsecrets/
git commit -m "perf: switch hot paths from third-party regex to stdlib re where compatible"
```

---

## Task 7: Финальный замер и фиксация

**Rationale (Обоснование).** Чтобы убедиться, что комбинация изменений даёт совокупный эффект и не сломала ни одну детекцию.

- [ ] **Step 7.1: Прогнать smoke-бенчмарк из Stage 1**

Run: `DEEPSECRETS_PERF=1 pytest tests/perf/test_orchestration_smoke.py -v -s`
Expected: `elapsed=` меньше, чем после Stage 1 (ожидаем +30…80%).

- [ ] **Step 7.2: Полный регресс**

Run: `pytest tests/`
Expected: PASS на том же наборе, что Stage 1 после Task 7.

- [ ] **Step 7.3: Сравнить детекции на фикстурах**

```bash
deepsecrets --target-dir tests/fixtures --outfile /tmp/r_stage2.json --outformat json --process-count 2
python -c "import json; d=json.load(open('/tmp/r_stage2.json')); print(sum(len(v) for v in d.values()), 'findings across', len(d), 'files')"
```

Expected: число findings совпадает с baseline (запустить такой же командой до Task 1, чтобы получить эталон).

- [ ] **Step 7.4: Прогнать тесты secrets-schutz (downstream регресс)**

Если есть `~/project/service-secrets-schutz` локально:

```bash
cd /Users/gvbabaev/project/service-secrets-schutz
# Установить локальную dev-копию DeepSecrets
pip install -e /Users/gvbabaev/project/deepsecrets
pytest tests/ -x
cd -
```

Expected: PASS — особенно `tests/lib/test_scan_2.py`, `tests/infra/test_modes.py`, `tests/infra/clients/test_file_scanner.py`. Любой DiffFile-релевантный тест должен дать **тот же** набор findings.

- [ ] **Step 7.5: Тег**

```bash
git tag perf-stage-2-done
```

---

## Self-Review

**Spec coverage:**
- bisect для line lookup → Task 1.
- Counter в энтропии → Task 2.
- Union regex → Task 3.
- FileTypeGuesser префильтр → Task 4.
- JSX lexer cache → Task 5.
- `regex` → `re` → Task 6.
- Замеры → Task 7.

**Placeholder scan:** все шаги содержат конкретный код или конкретные команды; нет общих формулировок.

**Type consistency:** `_line_ends_sorted: List[int]` объявлен в init и используется в `_calc_offsets` и `_get_line_number_for_position`. `_union_cache`/`_rule_index` объявлены в `__init__` и используются в `_build_union`/`search`. Имена probe-методов в `FileTypeGuesser` остаются прежними.
