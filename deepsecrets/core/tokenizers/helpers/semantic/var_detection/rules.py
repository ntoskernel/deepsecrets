import regex as re
from typing import List

from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import (
    CheapVariableDetector,
    Match,
    VariableDetector,
    VariableSuppressor,
)
from pygments.token import Token as PygmentsToken

'''
VariableDetector(
    language=Language.YAML,
    stream_pattern=re.compile('(n)(p)(L)'),
    match_rules={
        1: Match(types=[PygmentsToken.Name.Tag]),
        2: Match(values=[':']),
    },
    match_semantics={1: 'name', 3: 'value'},
),
'''


class VariableDetectionRules:
    rules = [
        VariableDetector(
            language=Language.PYTHON,
            stream_pattern=re.compile('(n)(o|p)(?:\n?)(L)(?:\n|p|\?)'),  # noqa
            match_rules={2: Match(values=[re.compile('^=$'), re.compile('^:$')])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.PYTHON,
            stream_pattern=re.compile('(L)(p)(L)(?:p|\n)'),
            match_rules={2: Match(values=[':'])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.PYTHON,
            stream_pattern=re.compile('(L)(p)(o)(L)'),
            match_rules={2: Match(values=[']']), 3: Match(values=['='])},
            match_semantics={1: 'name_token', 4: 'value_token'},
        ),
        VariableDetector(
            language=Language.PYTHON,
            stream_pattern=re.compile('(n)(o)(p).*(L)+.*(p)', flags=re.MULTILINE | re.S),
            match_rules={
                2: Match(values=['=']),
                3: Match(values=['(']),
                5: Match(values=[')']),
            },
            match_semantics={1: 'name_token', 4: 'value_token'},
        ),
        VariableDetector(
            language=Language.PYTHON,
            stream_pattern=re.compile('(n)(p)(L)(p)(L)', flags=re.MULTILINE | re.S),
            match_rules={
                1: Match(values=['getenv']),
                2: Match(values=['(']),
                4: Match(values=[',']),
            },
            match_semantics={3: 'name_token', 5: 'value_token'},
        ),
        # GOLANG
        VariableDetector(
            language=Language.GOLANG,
            stream_pattern=re.compile('(n)(o|p)(L)(?:p|\n)?'),
            match_rules={2: Match(values=[':', '=', ':='])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.GOLANG,
            stream_pattern=re.compile('(n)(p)(L)(?:p|\n)?(L)(p)'),
            match_rules={
                1: Match(values=['Setenv', 'Getenv']),
                2: Match(values=['(']),
                5: Match(values=[')']),
            },
            match_semantics={3: 'name_token', 4: 'value_token'},
        ),
        VariableDetector(
            language=Language.GOLANG,
            stream_pattern=re.compile('(n)(?:p|n|u){0,3}?(o).*(n)(p)(L)'),
            match_rules={
                2: Match(values=[':=']),
                3: Match(not_values=['Getenv', 'Setenv', 'Format']),
            },
            match_semantics={1: 'name_token', 5: 'value_token'},
        ),
        VariableDetector(
            language=Language.GOLANG,
            stream_pattern=re.compile('(n)(?:o|p){1,3}(\?|u)p(L)p'),  # noqa
            match_rules={2: Match(values=['byte', 'string'])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        # PHP
        VariableDetector(
            language=Language.PHP,
            stream_pattern=re.compile('(n|v|L)(o)(L)'),
            match_rules={2: Match(values=['=', '=>'])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.PHP,
            stream_pattern=re.compile('(L)(o)(n)(p)Lp(L)p'),
            match_rules={
                2: Match(values=['=>']),
                3: Match(values=['env']),
                4: Match(values=['(']),
            },
            match_semantics={1: 'name_token', 5: 'value_token'},
        ),
        # CONFIGS AND FORMATS
        VariableDetector(
            language=Language.TOML,
            stream_pattern=re.compile('(n)(o)(L)\n'),
            match_rules={2: Match(values=['='])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.YAML,
            stream_pattern=re.compile('(L)(p)(L)'),
            match_rules={2: Match(values=[':'])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.INI,
            stream_pattern=re.compile('(n)(o)(L)'),
            match_rules={2: Match(values=['='])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.PUPPET,
            stream_pattern=re.compile('(v|n)(o)(L)'),
            match_rules={2: Match(values=['=>', '='])},
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.ANY,
            stream_pattern=re.compile('(v|n)(p|o)(L)'),
            match_rules={
                2: Match(
                    values=[
                        re.compile('^:$'),
                        re.compile('^=$'),
                    ]
                )
            },
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.SHELL,
            stream_pattern=re.compile('(L)(L)(L)(L)'),
            match_rules={
                1: Match(values=[re.compile('^curl$')]),
                2: Match(values=[re.compile('^-u$')]),
                4: Match(not_values=[re.compile('^\\$')]),
            },
            match_semantics={3: 'name_token', 4: 'value_token'},
            creds_probability=9,
        ),
        VariableDetector(
            language=Language.CSHARP,
            stream_pattern=re.compile('(n).{0,6}(u|L)p(L)(p)'),
            match_rules={
                1: Match(values=[re.compile('^KeyValuePair$')]),
                4: Match(not_values=[re.compile('^}$')]),
            },
            match_semantics={2: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.CSHARP,
            stream_pattern=re.compile('(p)(.)(p)(L)(p)'),
            match_rules={
                1: Match(values=[re.compile('^{$')]),
                3: Match(values=[re.compile('^,$')]),
                5: Match(values=[re.compile('^}$')]),
            },
            match_semantics={2: 'name_token', 4: 'value_token'},
        ),
        VariableDetector(
            language=Language.JAVA,
            stream_pattern=re.compile('(n)(p)(.)(p)(L)'),
            match_rules={
                1: Match(values=[re.compile('^put$')]),
                2: Match(values=[re.compile('^\\($')]),
                4: Match(values=[re.compile('^,$')]),
            },
            match_semantics={3: 'name_token', 5: 'value_token'},
        ),
        VariableDetector(
            language=Language.MARKDOWN,
            stream_pattern=re.compile('(n)(p)(.)(p)(L)'),
            match_rules={
                1: Match(values=[re.compile('^put$')]),
                2: Match(values=[re.compile('^\\($')]),
                4: Match(values=[re.compile('^,$')]),
            },
            match_semantics={3: 'name_token', 5: 'value_token'},
        ),
        VariableDetector(
            language=Language.JS,
            stream_pattern=re.compile('(L)(o)(L)'),
            match_rules={
                1: Match(types=[PygmentsToken.Literal.String.Double, PygmentsToken.Literal.String.Single]),
                2: Match(values=[re.compile('^:$')]),
                3: Match(types=[PygmentsToken.Literal.String.Double, PygmentsToken.Literal.String.Single]),
            },
            match_semantics={1: 'name_token', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.JS,
            stream_pattern=re.compile('(n)(p)Lp(L)p'),
            match_rules={
                1: Match(values=[re.compile('^algoliasearch$')]),
                2: Match(values=[re.compile('^\\($')]),
            },
            match_semantics={'algolia_api_secret_key': 'name_override', 3: 'value_token'},
        ),
        VariableDetector(
            language=Language.JS,
            stream_pattern=re.compile('(n)p(n)p(n)(o)(L)'),
            match_rules={
                1: Match(values=[re.compile('^process$')]),
                2: Match(values=[re.compile('^env$')]),
                4: Match(values=[re.compile('^||')]),
            },
            match_semantics={3: 'name_token', 5: 'value_token'},
        ),
    ]

    @classmethod
    def for_language(cls, language: Language) -> List[VariableDetector]:
        return list(filter(lambda x: x.language in [language, Language.ANY], cls.rules))


class VariableSuppressionRules(VariableDetectionRules):
    rules = [
        VariableSuppressor(
            # For cases like <Tag key="ffda">
            language=Language.JS,
            stream_pattern=re.compile('(p)(n).+?(p)(u|L|\n|$)'),
            match_rules={
                1: Match(
                    values=[
                        re.compile('^<$'),
                        re.compile('^(}|{)$'),
                    ]
                ),
                2: Match(types=[PygmentsToken.Name.Tag, PygmentsToken.Name.Attribute]),
                3: Match(
                    values=[
                        re.compile('^>$'),
                        re.compile('^(}|{)$'),
                    ]
                ),
            },
            match_semantics={},
        ),
        VariableSuppressor(
            language=Language.JS,
            stream_pattern=re.compile('(n)(o)L.{0,4}(?:u|\n)?(n)(o)(?:L|u|n)'),
            match_rules={
                1: Match(
                    values=[
                        re.compile('^key$'),
                    ]
                ),
                2: Match(
                    values=[
                        re.compile('^:$'),
                    ]
                ),
                3: Match(
                    values=[
                        re.compile('^.*value.*$', flags=re.IGNORECASE),
                        re.compile('^.*name.*$', flags=re.IGNORECASE),
                        re.compile('^.*title.*$', flags=re.IGNORECASE),
                    ]
                ),
                4: Match(
                    values=[
                        re.compile('^:$'),
                    ]
                ),
            },
            match_semantics={},
        ),
        VariableSuppressor(
            language=Language.SWIFT,
            stream_pattern=re.compile('(n)(p)(n)(p)L'),
            match_rules={
                1: Match(values=[re.compile('^decode$'), re.compile('^decodeIfPresent$'), re.compile('^unbox$')]),
                2: Match(values=[re.compile('^\($')]),
                3: Match(values=[re.compile('^(key|keyPath)$')]),
                4: Match(values=[re.compile('^:$')]),
            },
            match_semantics={},
        ),
        VariableSuppressor(
            language=Language.GOLANG,
            stream_pattern=re.compile('(p)(n)(p)L(p)(n)(p).'),
            match_rules={
                1: Match(
                    values=[
                        re.compile('^{$'),
                    ]
                ),
                2: Match(
                    values=[
                        re.compile('^key$', re.IGNORECASE),
                    ]
                ),
                3: Match(
                    values=[
                        re.compile('^:$'),
                    ]
                ),
                4: Match(
                    values=[
                        re.compile('^,$'),
                    ]
                ),
                5: Match(
                    values=[
                        re.compile('^value$', re.IGNORECASE),
                    ]
                ),
                6: Match(
                    values=[
                        re.compile('^:$'),
                    ]
                ),
            },
            match_semantics={},
        ),
        VariableSuppressor(
            language=Language.JSON,
            stream_pattern=re.compile('(?=((n)pL(?:.|\n)*?(n)pL))'),
            match_rules={
                2: Match(values=[re.compile('.*key.*'), re.compile('.*value.*')]),
                3: Match(values=[re.compile('.*key.*'), re.compile('.*value.*')]),
            },
            match_semantics={},
            span_by_group_index=1,
        ),
    ]


class CheapVariableDetectionRules(VariableDetectionRules):
    rules = [
        # looking for generic key-value
        CheapVariableDetector(
            stream_pattern=re.compile('(["\'])([^\\[\\]"\'\\)\\(;\\s]+)\\1\\s*[:=]\\s*(["\'])([^\\[\\]"\';\\s]+)\\3'),
            match_rules={},
            match_semantics={2: 'name', 4: 'value'},
        ),
        # looking for random urls
        CheapVariableDetector(
            stream_pattern=re.compile('(?:\\:\\/\\/[^\n\r" ]*?|\\G)[?&]([^=&\\s]+)=([^&\\s"\',]*)'),
            match_rules={},
            match_semantics={1: 'name', 2: 'value'},
        ),
    ]
