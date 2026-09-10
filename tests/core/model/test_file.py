import pytest

from deepsecrets.core.model.file import File

LINE_BREAK = '\n'


@pytest.mark.fixture_file_path('4.go')
def test_basic_info(file: File):
    assert file.path == '/app/tests/fixtures/4.go'
    assert file.relative_path == 'tests/fixtures/4.go'
    assert file.extension == 'go'
    assert file.length == 395
    assert len(file.line_offsets) == 15


@pytest.mark.fixture_file_path('4.go')
def test_line_offsets(file):
    assert file.line_offsets[1] == (0, 48)
    assert file.content[48] == LINE_BREAK

    assert file.line_offsets[2] == (49, 152)
    assert file.content[152] == LINE_BREAK

    assert file.line_offsets[3] == (153, 154)
    assert file.content[154] == LINE_BREAK

    assert file.line_offsets[4] == (155, 194)
    assert file.content[194] == LINE_BREAK

    assert file.line_offsets[5] == (195, 240)
    assert file.content[240] == LINE_BREAK

    assert file.line_offsets[6] == (241, 293)
    assert file.content[293] == LINE_BREAK

    assert file.line_offsets[7] == (294, 294)
    assert file.content[294] == LINE_BREAK

    assert file.line_offsets[8] == (295, 311)
    assert file.content[311] == LINE_BREAK

    assert file.line_offsets[9] == (312, 325)
    assert file.content[325] == LINE_BREAK

    assert file.line_offsets[10] == (326, 328)
    assert file.content[328] == LINE_BREAK

    assert file.line_offsets[11] == (329, 358)
    assert file.content[358] == LINE_BREAK

    assert file.line_offsets[12] == (359, 375)
    assert file.content[375] == LINE_BREAK

    assert file.line_offsets[13] == (376, 389)
    assert file.content[389] == LINE_BREAK

    assert file.line_offsets[14] == (390, 392)
    assert file.content[392] == LINE_BREAK

    assert file.line_offsets[15] == (393, 394)
    assert file.content[394] == LINE_BREAK

    assert file.content[-1] == file.content[file.length - 1] == file.content[394] == '\n'


@pytest.mark.fixture_file_path('4.go')
def test_caching(file: File):
    LINUM = 4
    line_contents = file.get_line_contents(LINUM)
    assert line_contents == '''\ttest2 := os.Getenv(`TEST_TEST`, "lol")'''
    assert file.line_contents_cache[LINUM] == line_contents


@pytest.mark.fixture_file_path('4.go')
def test_get_full_line_for_position(file: File):
    POSITION = 94
    projected_line_number = 2
    line_contents = file.get_full_line_for_position(POSITION)
    assert (
        line_contents
        == '\tos.Setenv("RABBITMQ_URL", "amqp://fake_user:TESTSECRET1234@rabbitmq-esp01.miami.example.com:5672/esp")'
    )
    assert projected_line_number in file.line_contents_cache.keys()


@pytest.mark.fixture_file_path('4.go')
def test_get_line_number(file: File):
    POSITION = 94
    projected_line_number = 2
    line_number = file.get_line_number(POSITION)
    assert line_number == projected_line_number


@pytest.mark.fixture_file_path('4.go')
def test_1_span_for_string(file: File):
    looking_for = 'rabbitmq-esp01'
    span = file.get_span_for_string(looking_for)
    assert span == (109, 123)


@pytest.mark.fixture_file_path('4.go')
def test_2_span_for_string(file: File):
    looking_for = 'rabbitmq-esp01'
    span = file.get_span_for_string(looking_for, between=(130, 150))
    assert span is None


@pytest.mark.parametrize(
    "path, expected",
    [
        # a dot in a parent directory is not an extension
        ('/Users/john.doe/proj/credentials', None),
        ('/home/user.name/README', None),
        ('/builds/my.project/Dockerfile', None),
        ('/tmp/a.b/c.py', 'py'),
        ('/tmp/a.b/c.tar.gz', 'gz'),
        ('/tmp/a.b/.env', 'env'),
        ('/tmp/plain/credentials', None),
    ],
)
def test_extension_ignores_dotted_directories(path, expected):
    file = File(path=path, content='x = 1\n')
    assert file.extension == expected
