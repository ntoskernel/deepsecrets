from deepsecrets.core.model.semantic import Context


def test_1_context():
    ctx = Context(name='basicCamelCaseExample', value='', filepath='')
    assert ctx.name == 'basicCamelCaseExample'
    assert ctx.name_normalized == 'basiccamelcaseexample'
    assert ctx.name_parts == ['basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'basic camel case example'


def test_2_context():
    ctx = Context(name='BasicCamelCaseExample', value='', filepath='')
    assert ctx.name == 'BasicCamelCaseExample'
    assert ctx.name_normalized == 'basiccamelcaseexample'
    assert ctx.name_parts == ['basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'basic camel case example'


def test_3_context():
    ctx = Context(name='Basic_CamelCaseExample', value='', filepath='')
    assert ctx.name == 'Basic_CamelCaseExample'
    assert ctx.name_normalized == 'basiccamelcaseexample'
    assert ctx.name_parts == ['basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'basic camel case example'


def test_4_context():
    ctx = Context(name='extra_basicCamelCaseExample', value='', filepath='')
    assert ctx.name == 'extra_basicCamelCaseExample'
    assert ctx.name_normalized == 'extrabasiccamelcaseexample'
    assert ctx.name_parts == ['extra', 'basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'extra basic camel case example'


def test_5_context():
    ctx = Context(name='Another-extra_basicCamelCaseExample', value='', filepath='')
    assert ctx.name == 'Another-extra_basicCamelCaseExample'
    assert ctx.name_normalized == 'anotherextrabasiccamelcaseexample'
    assert ctx.name_parts == ['another', 'extra', 'basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'another extra basic camel case example'


def test_6_context():
    ctx = Context(name='another extra_basicCamelCaseExample', value='', filepath='')
    assert ctx.name == 'another extra_basicCamelCaseExample'
    assert ctx.name_normalized == 'anotherextrabasiccamelcaseexample'
    assert ctx.name_parts == ['another', 'extra', 'basic', 'camel', 'case', 'example']
    assert ctx.name_spaced == 'another extra basic camel case example'


def test_7_context():
    ctx = Context(name='data-sitekey', value='', filepath='')
    assert ctx.name == 'data-sitekey'
    assert ctx.name_normalized == 'datasitekey'
    assert ctx.name_parts == ['data', 'sitekey']
    assert ctx.name_spaced == 'data sitekey'
