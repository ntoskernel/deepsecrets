"""Instrumented replay of one file: selection, lexer, tokens, variable detection and suppression, the post-filter,
the semantic engine's gates, the variable evaluator rule by rule, the per-file value cache, regex hits and merging.

Input is a list of spans (a line and column range, plus the expected value) inside one file; output is one trace per
span. The verdict names the first stage where an expected secret was lost, or, for a reported value, which engine and
rule produced it and what drove its score. The schema is versioned: consumers (the benchmark harness) depend on it.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine, filenames_ignorelist
from deepsecrets.core.helpers.variable_evaluator import HOPELESS_THRESHOLD, VariableEvaluator
from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import SemanticType, Token
from deepsecrets.core.rulesets.excluded_paths import ExcludedPathsBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.tokenizers.cheap_var_search import CheapVarSearchTokenizer
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.helpers.semantic.deep_analyzer import DeepAnalyzer
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.rules import (
    VariableDetectionRules,
    VariableSuppressionRules,
)
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import EngineWithTokenizer, FileAnalyzer
from deepsecrets.core.utils.finding_merger import FindingMerger
from deepsecrets.core.utils.fs import get_path_inside_package

SCHEMA_VERSION = 1
WINDOW_BEFORE, WINDOW_AFTER = 6, 3


@dataclass
class Rulesets:
    regex: list
    scoring: list
    excluded: list

    @classmethod
    def builtin(cls, path_exclusions: bool = True) -> 'Rulesets':
        """The shipped rulesets. `path_exclusions=False` mirrors a scan run with `--excluded-paths disable`, so a
        file under node_modules/ is replayed instead of stopping at the selection stage."""
        regex = RegexRulesetBuilder()
        regex.with_rules_from_file(get_path_inside_package('rules/regexes.json'))
        scoring = VariableScoringRulesetBuilder()
        scoring.with_rules_from_file(get_path_inside_package('rules/variable_scoring_rules.json'))
        excluded = ExcludedPathsBuilder()
        if path_exclusions:
            excluded.with_rules_from_file(get_path_inside_package('rules/excluded_paths.json'))
        return cls(regex=regex.rules, scoring=scoring.rules, excluded=excluded.rules)


@dataclass
class Span:
    case_id: str
    line: int
    end_line: int
    start_col: int
    end_col: int
    value: str
    start: Optional[int] = None
    end: Optional[int] = None
    located: bool = False


class TracingFileAnalyzer(FileAnalyzer):
    """FileAnalyzer with the per-token decisions of `_run_engine` recorded: skipped by the value cache, findings."""

    def __init__(self, file: File) -> None:
        super().__init__(file)
        self.decisions: List[dict] = []

    def _run_engine(self, et: EngineWithTokenizer):
        results = []
        processed_values: Dict[int, bool] = {}
        if et.tokenizer not in self.tokens:
            self.tokens[et.tokenizer] = et.tokenizer.tokenize(self.file)
        name = et.tokenizer.__class__.__name__
        for token in self.tokens[et.tokenizer]:
            known = processed_values.get(token.val_hash())
            if known is not None and known is False:
                self.decisions.append(
                    {'tokenizer': name, 'engine': et.engine.name, 'span': token.span, 'cache_skip': True}
                )
                continue
            processed_values[token.val_hash()] = False
            findings = et.engine.search(token)
            for finding in findings:
                finding.map_on_file(file=self.file, relative_start=token.span[0])
                results.append(finding)
                processed_values[token.val_hash()] = True
            self.decisions.append(
                {
                    'tokenizer': name,
                    'engine': et.engine.name,
                    'span': token.span,
                    'cache_skip': False,
                    'findings': len(findings),
                }
            )
        return results


def _overlaps(span, start: int, end: int) -> bool:
    return span is not None and span[0] < end and start < span[1]


def _rule_ref(rule, rules) -> str:
    index = next((i for i, r in enumerate(rules) if r is rule), -1)
    language = getattr(rule, 'language', None)
    return f'{getattr(language, "name", language)}#{index}'


def _type_name(token: Token) -> str:
    return '.'.join(str(token.type[0]).split('.')[1:]) if token.type else '?'


def _locate(file: File, span: Span) -> None:
    offsets = file.line_offsets
    if span.line not in offsets:
        return
    line_start = offsets[span.line][0]
    candidate = line_start + max(span.start_col, 1) - 1
    if file.content[candidate : candidate + len(span.value)] == span.value:
        span.start, span.end, span.located = candidate, candidate + len(span.value), True
        return
    last = offsets.get(max(span.end_line, span.line), offsets[span.line])[1]
    found = file.content.find(span.value, line_start, last + 1) if span.value else -1
    if found != -1:
        span.start, span.end, span.located = found, found + len(span.value), True
        return
    # the value is not at the labelled place: keep the column range so tokens there can still be described
    span.start = candidate
    span.end = line_start + max(span.end_col, span.start_col + 1) - 1


def _evaluate(evaluator: VariableEvaluator, scoring_rules: list, variable) -> dict:
    context = variable.context
    running, fired, hopeless = 0, [], False
    for rule in scoring_rules:
        if rule.match_by_context(context):
            running += rule.score
            fired.append({'id': rule.id, 'score': rule.score, 'running': running})
        if running <= HOPELESS_THRESHOLD:
            hopeless = True
            break
    result = evaluator.evaluate(variable)
    counterfactual = {}
    for entry in fired:
        without = VariableEvaluator([r for r in scoring_rules if r.id != entry['id']])
        counterfactual[entry['id']] = without.evaluate(variable).is_dangerous
    return {
        'name': context.name,
        'rules': fired,
        'hopeless_exit': hopeless,
        'naming_score': result.naming_and_content_score if not hopeless else running,
        'entropy': round(result.entropy, 3),
        'entropy_score': round(result.entropy_score, 2),
        'naturalness': round(1 - result.nonsence_value_score, 3) if not hopeless else None,
        'dangerous': result.is_dangerous,
        'confidence': result.export_confidence,
        'rule_emitted': ('S105' if result.entropy_score > 0 else 'S106') if result.is_dangerous else None,
        'dangerous_without': counterfactual,
    }


def _gate(token: Token, file: File) -> Optional[str]:
    """SemanticEngine.search's early returns, in its order."""
    if token.length == file.length:
        return 'whole_file_token'
    if any(name in (file.path or '') for name in filenames_ignorelist):
        return 'ignored_file_name'
    if len(token.content) == 1:
        return 'single_character'
    if len(token.content.split(' ')) > 1:
        return 'contains_space'
    return None


@dataclass
class FileReplay:
    file: File
    relative_path: str
    rulesets: Rulesets
    lexer_name: Optional[str] = None
    language: Optional[str] = None
    raw_tokens: List[Token] = field(default_factory=list)
    stream: str = ''
    detections: List[dict] = field(default_factory=list)
    prefilter_vars: List[Token] = field(default_factory=list)
    production_vars: List[Token] = field(default_factory=list)
    cheap_vars: List[Token] = field(default_factory=list)
    findings: list = field(default_factory=list)
    decisions: List[dict] = field(default_factory=list)
    excluded_by: Optional[str] = None

    def run(self) -> 'FileReplay':
        for rule in self.rulesets.excluded:
            if rule.match(self.relative_path):
                self.excluded_by = rule.pattern.pattern
                break

        # tokens and regions before any variable analysis, with the type stream the detection rules read
        raw = LexerTokenizer(deep_token_inspection=False)
        raw.tokenize(self.file, post_filter=False)
        self.lexer_name = raw.lexer.name if raw.lexer else None
        self.language = getattr(getattr(raw, 'language', None), 'name', None)
        self.raw_tokens, self.stream = list(raw.tokens), raw.token_stream

        detection_rules = VariableDetectionRules.rules
        for region in getattr(raw, 'regions', None) or []:
            if region.language is None:
                continue
            spans = []
            for rule in VariableSuppressionRules.for_language(region.language):
                spans.extend(rule.match(region.tokens, region.stream))
            # the same collapsing DeepAnalyzer applies before it checks containment
            spans = DeepAnalyzer([], post_filter=False)._collapse_suppression_regions(spans)
            for rule in VariableDetectionRules.for_language(region.language):
                for var in rule.match(region.tokens, region.stream):
                    suppressor = next((s for s in spans if var.span[0] >= s[0] and var.span[1] <= s[1]), None)
                    name_line = self.file.get_line_number(var.name_token.span[0]) if var.name_token else None
                    value_line = self.file.get_line_number(var.value_token.span[0]) if var.value_token else None
                    self.detections.append(
                        {
                            'rule': _rule_ref(rule, detection_rules),
                            'region_language': getattr(region.language, 'name', None),
                            'name': var.name_token.content if var.name_token else getattr(var, 'name_override', None),
                            'value_span': var.value_token.span if var.value_token else None,
                            'name_value_lines_apart': (value_line - name_line) if name_line and value_line else None,
                            'suppressed_by': list(suppressor) if suppressor else None,
                            'creds_probability': rule.creds_probability,
                        }
                    )

        pre = LexerTokenizer(deep_token_inspection=True)
        pre.tokenize(self.file, post_filter=False)
        self.prefilter_vars = pre.get_variables()
        prod = LexerTokenizer(deep_token_inspection=True)
        prod.tokenize(self.file)
        self.production_vars = prod.get_variables()
        cheap = CheapVarSearchTokenizer()
        cheap.tokenize(self.file)
        self.cheap_vars = cheap.get_variables()

        # the production pipeline for this file, as scan_modes/cli.py builds it, with the value cache recorded
        regex_engine = RegexEngine(ruleset=self.rulesets.regex)
        semantic_engine = SemanticEngine(regex_engine, ruleset=self.rulesets.scoring)
        analyzer = TracingFileAnalyzer(self.file)
        analyzer.add_engine(regex_engine, [FullContentTokenizer()])
        analyzer.add_engine(semantic_engine, [LexerTokenizer(deep_token_inspection=True), CheapVarSearchTokenizer()])
        self.findings = FindingMerger(analyzer.process()).merge()
        self.decisions = analyzer.decisions
        return self

    def window(self, index: int) -> Optional[str]:
        if len(self.stream) != len(self.raw_tokens):
            return None
        before = self.stream[max(0, index - WINDOW_BEFORE) : index]
        after = self.stream[index + 1 : index + 1 + WINDOW_AFTER]
        return (before + '[' + self.stream[index] + ']' + after).replace('\n', '⏎')


def _trace_span(replay: FileReplay, span: Span, evaluator: VariableEvaluator) -> dict:
    file = replay.file
    # a label whose line is not in the file overlaps nothing
    s, e = (span.start, span.end) if span.start is not None else (-1, -1)
    trace = {
        'schema': SCHEMA_VERSION,
        'case_id': span.case_id,
        'located': span.located,
        'selection': {'excluded_by': replay.excluded_by},
        'lexer': {'name': replay.lexer_name, 'language': replay.language, 'extension': file.extension},
    }

    covering = [i for i, t in enumerate(replay.raw_tokens) if _overlaps(t.span, s, e)]
    if covering:
        first = replay.raw_tokens[covering[0]]
        contain = (
            'split' if len(covering) > 1 else ('exact' if first.span[0] == s and first.span[1] == e else 'embedded')
        )
        trace['token'] = {
            'type': _type_name(first),
            'contain': contain,
            'in_comment': any('Comment' in str(t) for t in first.type),
            'window': replay.window(covering[0]),
        }
    else:
        trace['token'] = None

    detections = [d for d in replay.detections if _overlaps(d['value_span'], s, e)]
    trace['detections'] = detections
    in_pre = [t for t in replay.prefilter_vars if _overlaps(t.span, s, e)]
    in_prod = [t for t in replay.production_vars if _overlaps(t.span, s, e)]
    in_cheap = [t for t in replay.cheap_vars if _overlaps(t.span, s, e)]
    trace['variables'] = {'lex_prefilter': bool(in_pre), 'lex': bool(in_prod), 'cheap': bool(in_cheap)}

    evaluations = []
    for source, tokens in (('lex', in_prod), ('cheap', in_cheap)):
        for token in tokens:
            if token.semantic is None or token.semantic.type != SemanticType.VARIABLE:
                continue
            entry = {'source': source, 'value_exact': token.span[0] == s and token.span[1] == e}
            entry['gate'] = _gate(token, file)
            if token.semantic.creds_probability == 9:
                entry['s107'] = True
            if entry['gate'] is None:
                entry.update(_evaluate(evaluator, replay.rulesets.scoring, token.semantic.payload))
            evaluations.append(entry)
    trace['evaluations'] = evaluations

    cache_skips = [
        d['tokenizer']
        for d in replay.decisions
        if d['cache_skip'] and d['engine'] == 'semantic' and _overlaps(d['span'], s, e)
    ]
    reported = [f for f in replay.findings if f.start_offset < e and s < f.end_offset]
    trace['production'] = {
        'findings': [
            {
                'rule': f.final_rule.id if f.final_rule else f.rules[0].id,
                'confidence': max(r.confidence for r in f.rules),
                'exact': f.start_offset == s and f.end_offset == e,
            }
            for f in (_with_final_rule(f) for f in reported)
        ],
        'cache_skipped': sorted(set(cache_skips)),
    }
    trace['verdict'] = _verdict(trace)
    return trace


def _with_final_rule(finding):
    finding.choose_final_rule()
    return finding


def _verdict(t: dict) -> dict:
    """The first stage that explains a missing value; for a reported value, what reported it."""
    if t['production']['findings']:
        rules = sorted({f['rule'] for f in t['production']['findings']})
        semantic = any(r.split('-')[0] in ('S105', 'S106', 'S107') for r in rules)
        return {
            'stage': 'reported',
            'component': 'semantic_engine' if semantic else 'regex_engine',
            'detail': ','.join(rules),
        }
    if t['selection']['excluded_by']:
        return {'stage': 'selection', 'component': 'excluded_paths', 'detail': t['selection']['excluded_by']}
    if not t['located']:
        return {'stage': 'label', 'component': 'dataset', 'detail': 'value not found where the label points'}
    has_cheap = t['variables']['cheap']
    if t['lexer']['name'] is None and not has_cheap:
        return {'stage': 'lexer', 'component': 'lexer_finder', 'detail': 'no lexer'}
    if t['token'] is None and not has_cheap:
        return {'stage': 'token', 'component': 'lexer_tokenizer', 'detail': 'no token covers the value'}
    if not t['detections'] and not has_cheap:
        detail = 'in a comment' if (t['token'] or {}).get('in_comment') else 'no detection rule matched'
        return {'stage': 'detection', 'component': 'variable_detection', 'detail': detail}
    if t['detections'] and all(d['suppressed_by'] for d in t['detections']) and not has_cheap:
        return {'stage': 'detection', 'component': 'variable_suppression', 'detail': 'suppressed'}
    if t['variables']['lex_prefilter'] and not t['variables']['lex'] and not has_cheap:
        return {'stage': 'post_filter', 'component': 'deep_analyzer', 'detail': 'removed by final_cleanup'}
    evaluations = t['evaluations']
    if not evaluations:
        return {
            'stage': 'detection',
            'component': 'variable_detection',
            'detail': 'detected but no variable reached the engine',
        }
    if all(ev.get('gate') for ev in evaluations):
        return {'stage': 'gate', 'component': 'semantic_engine', 'detail': evaluations[0]['gate']}
    if any(ev.get('dangerous') for ev in evaluations):
        if t['production']['cache_skipped']:
            return {
                'stage': 'emission',
                'component': 'file_analyzer',
                'detail': 'value cache: seen earlier with no finding',
            }
        return {'stage': 'emission', 'component': 'finding_merger', 'detail': 'dangerous but not reported'}
    return {'stage': 'evaluation', 'component': 'variable_evaluator', 'detail': 'scored as not dangerous'}


def trace_file(path: str, relative_path: str, spans: List[dict], rulesets: Optional[Rulesets] = None) -> List[dict]:
    """One trace per span. `spans` items: case_id, line, end_line, start_col, end_col, value."""
    rulesets = rulesets or Rulesets.builtin()
    file = File(path=path, relative_path=relative_path)
    replay = FileReplay(file=file, relative_path=relative_path, rulesets=rulesets).run()
    evaluator = VariableEvaluator(rulesets.scoring)
    traces = []
    for raw in spans:
        span = Span(
            case_id=str(raw['case_id']),
            line=int(raw['line']),
            end_line=int(raw.get('end_line') or raw['line']),
            start_col=int(raw.get('start_col') or 1),
            end_col=int(raw.get('end_col') or 1),
            value=raw.get('value') or '',
        )
        _locate(file, span)
        traces.append(_trace_span(replay, span, evaluator))
    return traces
