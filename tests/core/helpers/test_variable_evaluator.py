from deepsecrets.core.helpers.variable_evaluator import EvaluationResult, VariableEvaluator
from deepsecrets.core.model.semantic import Context


def test_0(variable_scoring_rules):
    ctx = Context(name='SERVICE_OAUTH', value='aaa', filepath='good')
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)

    assert result.is_dangerous is False
    assert 'SEM_VAR_VALUE_LENGTH' in result.matched_rules
    assert result.export_confidence == 0


def test_1(variable_scoring_rules):
    ctx = Context(name='SERVICE_OAUTH', value='vhpn6mbsvhpn6mbsvhpn6mbsvhpn6mbs', filepath='good')
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)

    assert result.is_dangerous is True and result.nonsence_value_score >= 0.5
    assert result.export_confidence >= 7


def test_2(variable_scoring_rules):
    # Cisco_cisco_key:"shape=mxgraph.cisco.misc.key;fillColor=#036897;strokeColor=#ffffff"
    ctx = Context(
        name='Cisco_cisco_key',
        value='shape=mxgraph.cisco.misc.key;fillColor=#036897;strokeColor=#ffffff',
        filepath='some.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False and result.nonsence_value_score < 0.5


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
    assert result.export_confidence >= 6


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
    assert result.export_confidence <= 6


def test_9(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='savingStatusKey',
        value='saving',
        filepath='2.conf',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False


def test_10(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='sporkprivkey',
        value='cW2YM2xaeCaebfpKguBahUAgEzLXgSserWRuD29kSyKHq1TTgwRQ',
        filepath='2.py',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 7


def test_11(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='client_secret',
        value='5846d428b5340812b76c9637eceaee979340b922',
        filepath='1.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 7


def test_12(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='minisign_key',
        value='YDXm6SYJNH9p53tsFljV4PgA51ANWwcDbjUZJo1JIT0XAhSu73F7NMV3',
        filepath='1.py',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 7


def test_13(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='borderDesign',
        value='headline',
        filepath='1.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False


def test_14(variable_scoring_rules):
    # input_token: MaxRecords
    ctx = Context(
        name='VSMSignalKanbanBlock',
        value='shape=triangle;direction=south;anchorPointDirection=0',
        filepath='1.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is False


def test_15(variable_scoring_rules):
    ctx = Context(
        name='bugsnag_key',
        value='ae7bc49d1285848342342bb5c321a2cf',
        filepath='1.min.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 4


def test_16(variable_scoring_rules):
    ctx = Context(
        name='SLOBS_STREAM_KEY',
        value='live_137546668_M4qFRbcNbYwEzVP5Ljgrexq2lZ5BX6',
        filepath='1.js',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 8


def test_17(variable_scoring_rules):
    ctx = Context(
        name='db_pass',
        value='nacc6opq',
        filepath='1.py',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 6


def test_18(variable_scoring_rules):
    ctx = Context(
        name='Mytoken',
        value='13572850-V1bz11ZrIGoGpqCOJw8mhwBfoswbVjWCA',
        filepath='ssifier.md',
    )
    ve = VariableEvaluator(variable_scoring_rules)
    result: EvaluationResult = ve.evaluate(ctx)
    assert result.is_dangerous is True
    assert result.export_confidence >= 6
