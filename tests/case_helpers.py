from typing import List
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.rulesets.variable_scoring import VariableScoringRulesetBuilder
from deepsecrets.core.tokenizers.cheap_var_search import CheapVarSearchTokenizer
from deepsecrets.core.tokenizers.itokenizer import Tokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer
from deepsecrets.core.utils.finding_merger import FindingMerger
from deepsecrets.core.utils.fs import get_path_inside_package


def run(file, engine, tokenizer):
    fa = FileAnalyzer(file)
    fa.add_engine(engine, [tokenizer])
    findings: List[Finding] = fa.process()
    findings = FindingMerger(findings).merge(choose_final_rule=True)
    return findings, tokenizer.tokens, tokenizer.get_variables()


def semantic_case(file: File):
    builder = VariableScoringRulesetBuilder()
    builder.with_rules_from_file(get_path_inside_package('rules/variable_scoring_rules.json'))
    engine = SemanticEngine(ruleset=builder.rules)
    tokenizer = LexerTokenizer(deep_token_inspection=True)
    return run(file, engine, tokenizer)


def semantic_case_with_cheap_var_search(file: File):
    builder = VariableScoringRulesetBuilder()
    builder.with_rules_from_file(get_path_inside_package('rules/variable_scoring_rules.json'))
    engine = SemanticEngine(ruleset=builder.rules)
    tokenizer = CheapVarSearchTokenizer()
    return run(file, engine, tokenizer)


def regex_case(tokenizer: Tokenizer, engine: RegexEngine, file: File):
    return run(file, engine, tokenizer)


def variable_detection_case(tokenizer: LexerTokenizer, file: File, post_filter=False):
    tokenizer.tokenize(file, post_filter=post_filter)
    return tokenizer.get_variables(), tokenizer.lexer, tokenizer.tokens


def cheap_variable_search_case(tokenizer: CheapVarSearchTokenizer, file: File, post_filter=False):
    tokenizer.tokenize(file)
    return tokenizer.get_variables(), None, tokenizer.tokens
