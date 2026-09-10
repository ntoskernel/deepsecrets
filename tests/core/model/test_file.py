import pickle
import random

import pytest
import regex as re

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


def _regex_span_reference(file: File, needle: str, between):
    # the escaped-regex implementation get_span_for_string used before it became a substring search
    if between is None:
        between = (0, file.length)
    between = [max(between[0], 0), min(between[1], file.length)]
    pattern = re.escape(needle).replace('\\\n', '\n').replace('\\\t', '\t')
    for detect in re.finditer(pattern, file.content[between[0] : between[1]]):
        return (between[0] + detect.span()[0], between[0] + detect.span()[1])
    return None


SPAN_CONTENT = 'a = "x.y*z"\n\tb = \'(a|b)\' # [] {1,2} ^$ \\d+\na = "x.y*z"\n\n'


@pytest.mark.parametrize(
    "needle, between",
    [
        ('"x.y*z"', None),
        ('"x.y*z"', [5, 70]),  # second occurrence only
        ('(a|b)', None),
        ('\tb', None),  # tab un-escaping
        ('z"\n\tb', None),  # newline inside the needle
        ('[] {1,2} ^$ \\d+', None),
        ('\n\n', None),
        ('missing', None),
        ('a', [3, 3]),  # empty window
        ('', [4, 9]),  # empty needle
        ('a =', [-5, 500]),  # clamped window
    ],
)
def test_span_for_string_matches_regex_reference(needle, between):
    file = File(path=None, content=SPAN_CONTENT)
    expected = _regex_span_reference(file, needle, list(between) if between else None)
    assert file.get_span_for_string(needle, between=list(between) if between else None) == expected


def test_span_for_string_randomized_against_regex_reference():
    rnd = random.Random(5)
    alphabet = 'ab.*()[]\\\n\t "\''
    content = ''.join(rnd.choice(alphabet) for _ in range(400))
    file = File(path=None, content=content)
    for _ in range(2000):
        start = rnd.randrange(0, len(content))
        needle = content[start : start + rnd.randrange(1, 6)]
        lo = rnd.randrange(-3, len(content))
        between = [lo, lo + rnd.randrange(0, 60)]
        assert file.get_span_for_string(needle, between=list(between)) == _regex_span_reference(file, needle, between)


def test_span_for_string_still_clamps_list_windows_in_place():
    # callers rely on this side effect staying as it was (KI-DM-04)
    file = File(path=None, content='abc\n')
    between = [-2, 99]
    assert file.get_span_for_string('bc', between=between) == (1, 3)
    assert between == [0, 4]


def _linear_line_reference(file: File, position: int):
    for linum, offsets in file.line_offsets.items():
        if offsets[1] < position:
            continue
        return linum
    return None


@pytest.mark.parametrize(
    "content",
    [
        'one\ntwo\n\nfour\n',
        'no trailing newline\nsecond',
        'abc',  # single line without newline: non-ascending line ends (KI-DM-03)
        '\n\n\n',
    ],
)
def test_line_lookup_matches_linear_reference(content):
    file = File(path=None, content=content)
    for position in range(-1, file.length + 3):
        assert file.get_line_number(position) == _linear_line_reference(file, position)


@pytest.mark.fixture_file_path('4.go')
def test_line_lookup_matches_linear_reference_on_fixture(file: File):
    for position in range(0, file.length + 2):
        assert file.get_line_number(position) == _linear_line_reference(file, position)


def test_line_lookup_with_supplied_offsets():
    file = File(path=None, content='ab\ncd\n', offsets={1: (0, 2), 2: (3, 5)})
    assert [file.get_line_number(p) for p in range(0, 7)] == [1, 1, 1, 2, 2, 2, None]


def test_line_index_is_not_pickled_and_is_rebuilt():
    file = File(path=None, content='one\ntwo\n')
    assert file.get_line_number(5) == 2
    assert file._line_index is not None

    clone = pickle.loads(pickle.dumps(file))
    assert '_line_index' not in clone.__dict__
    assert clone.get_line_number(5) == 2
