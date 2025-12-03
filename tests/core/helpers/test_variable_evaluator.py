from deepsecrets.core.helpers.variable_evaluator import EvaluationResult, VariableEvaluator
from deepsecrets.core.model.semantic import Context


def test_1(variable_scoring_rules):
    ctx = Context(name='SERVICE_OAUTH', value='vhpn6mbsvhpn6mbsvhpn6mbsvhpn6mbs', filepath='good')
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)

    assert result.is_dangerous is True and result.nonsence_value_score >= 0.5


def test_2(variable_scoring_rules):
    # Cisco_cisco_key:"shape=mxgraph.cisco.misc.key;fillColor=#036897;strokeColor=#ffffff"
    ctx = Context(
        name='Cisco_cisco_key',
        value='shape=mxgraph.cisco.misc.key;fillColor=#036897;strokeColor=#ffffff',
        filepath='some.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True and result.nonsence_value_score < 0.5


def test_3(variable_scoring_rules):
    # data-fp-apikey="AFcwrT3qvREad1lGpKXXWz"
    ctx = Context(
        name='data-fp-apikey',
        value='AFcwrT3qvREad1lGpKXXWz',
        filepath='nice.html',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True and result.nonsence_value_score > 0.5


def test_4(variable_scoring_rules):
    # result_key: GameSessions
    ctx = Context(
        name='result_key',
        value='GameSessions',
        filepath='one.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False and result.nonsence_value_score < 0.5


def test_5(variable_scoring_rules):
    # limit_key: VpcEndpointConnections
    ctx = Context(
        name='limit_key',
        value='VpcEndpointConnections',
        filepath='one.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False
    assert result.nonsence_value_score < 0.5


def test_6(variable_scoring_rules):
    # output_token: PolicyDescriptions
    ctx = Context(
        name='output_token',
        value='PolicyDescriptions',
        filepath='one.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False and result.nonsence_value_score < 0.5


def test_7(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='input_token',
        value='MaxRecords',
        filepath='one.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False and result.nonsence_value_score < 0.5


def test_8(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='key',
        value='eek05SKgALpQQg20ASrCzm1ZF7o',
        filepath='2.conf',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True and result.nonsence_value_score >= 0.5
