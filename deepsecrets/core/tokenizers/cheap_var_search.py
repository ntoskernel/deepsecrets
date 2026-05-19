from typing import List

from deepsecrets.core.model.file import File
from deepsecrets.core.model.semantic import Variable
from deepsecrets.core.model.token import Semantic, SemanticType, Token
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.rules import CheapVariableDetectionRules
from deepsecrets.core.tokenizers.itokenizer import Tokenizer


class CheapVarSearchTokenizer(Tokenizer):

    def tokenize(self, file: File) -> List[Token]:
        rules = CheapVariableDetectionRules.rules
        vars: List[Variable] = []
        for rule in rules:
            vars.extend(rule.match(file.content))

        for variable in vars:
            name_token = Token(
                file=file, content=variable.name, span=file.get_span_for_string(variable.name, variable.span)
            )
            variable.name_token = name_token

            value_token = Token(
                file=file, content=variable.value, span=file.get_span_for_string(variable.value, variable.span)
            )
            variable.value_token = value_token
            variable.value_token.semantic = Semantic(
                type=SemanticType.VARIABLE,
                payload=variable,
                creds_probability=variable.found_by.creds_probability,
            )
            self.tokens.append(value_token)

        return self.tokens
