from typing import List
from pydantic import RootModel
from deepsecrets.core.model.rules.regex import RegexRuleWithoutId


class ExcludePathRule(RegexRuleWithoutId):
    disabled: bool = False



class ExcludePatternsList(RootModel[List[ExcludePathRule]]):
    pass
