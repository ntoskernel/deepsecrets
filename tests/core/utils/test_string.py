from deepsecrets.core.utils.string import StringUtils

def test_camel_case_divide():
    example = 'someCoolVariableName'
    result = StringUtils.camel_case_divide(example)
    assert result == 'some cool variable name'