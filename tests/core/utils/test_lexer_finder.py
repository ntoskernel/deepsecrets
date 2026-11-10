import pytest
from deepsecrets.core.model.file import File
from deepsecrets.core.utils.lexer_finder import LexerFinder


@pytest.mark.fixture_file_path('extless/json')
def test_extless_json(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'JSON'


@pytest.mark.fixture_file_path('extless/ini')
def test_extless_ini(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'INI'


@pytest.mark.fixture_file_path('extless/yaml')
def test_extless_yaml(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'YAML'


@pytest.mark.fixture_file_path('3.js')
def test_js_react(file: File):
    lexer = LexerFinder().find(file)
    assert lexer.name == 'JSX'


# 2.3 (R1): configuration files that got no lexer. Written to tmp_path: a fixture named .env cannot be committed
# (KI-TEST-13), and nothing under tests/fixtures moves the whole-tree counts
NAME_VALUE = 'DB_PASSWORD=Xk9mQ2vLp4Rt\nAPI_KEY=Hk3vQ9ZpL2mXw7Rt\n'


def find(tmp_path, name: str, content: str):
    path = tmp_path / name
    path.write_text(content)
    lexer = LexerFinder().find(File(path=str(path), relative_path=name))
    return lexer.name if lexer is not None else None


@pytest.mark.parametrize(
    'name, content, lexer',
    [
        # NAME=VALUE files: the guesser, whose sectionless-INI probe fits them
        ('.env', NAME_VALUE, 'INI'),
        ('x.env', NAME_VALUE, 'INI'),
        ('.env.local', NAME_VALUE, 'INI'),
        ('.env.production', NAME_VALUE, 'INI'),
        ('.env.example', NAME_VALUE, 'INI'),
        ('.npmrc', 'registry=https://registry.npmjs.org/\n_auth=Xk9mQ2vLp4Rt\n', 'INI'),
        ('.pypirc', '[pypi]\nusername = __token__\npassword = Xk9mQ2vLp4Rt\n', 'INI'),
        ('.flaskenv', 'FLASK_APP=app.py\nSECRET_KEY=Xk9mQ2vLp4Rt\n', 'INI'),
        # XML formats Pygments does not know: the xml path, guesser then the HTML swap
        ('web.config', '<configuration><add key="apiPassword" value="Xk9mQ2vLp4Rt"/></configuration>\n', 'HTML'),
        ('App.csproj', '<Project/>\n', 'HTML'),
        ('Package.nuspec', '<package/>\n', 'HTML'),
        ('Product.wxs', '<Wix/>\n', 'HTML'),
        ('Directory.Build.props', '<Project/>\n', 'HTML'),
        ('Build.targets', '<Project/>\n', 'HTML'),
        # Markdown dialects
        ('page.mdx', '# Title\n', 'Markdown'),
        ('report.Rmd', '# Title\n', 'Markdown'),
        ('report.rmd', '# Title\n', 'Markdown'),
        # Dockerfiles: the Docker lexer, before the guesser reads them as YAML
        ('Dockerfile', 'FROM python:3.11\nENV DB_PASSWORD=Xk9mQ2vLp4Rt\n', 'Docker'),
        ('Dockerfile.prod', 'FROM python:3.11\n', 'Docker'),
        ('dockerfile', 'FROM python:3.11\n', 'Docker'),
        # a meta extension in another case still reaches the guesser (and xml its HTML swap)
        ('a.TXT', 'password=adminadmin\n', 'INI'),
        ('a.Conf', 'password=adminadmin\n', 'INI'),
        ('a.XML', '<a b="c"/>\n', 'HTML'),
    ],
)
def test_a_config_file_gets_a_lexer(tmp_path, name, content, lexer):
    assert find(tmp_path, name, content) == lexer


@pytest.mark.parametrize(
    'name, content, lexer',
    [
        ('settings.yml.example', 'password: Xk9mQ2vLp4Rt\n', 'YAML'),
        ('settings.py.sample', 'password = "Xk9mQ2vLp4Rt"\n', 'Python'),
        ('config.json.dist', '{"password": "Xk9mQ2vLp4Rt"}\n', 'JSON'),
        ('values.yaml.template', 'password: Xk9mQ2vLp4Rt\n', 'YAML'),
        ('index.html.tpl', '<p>x</p>\n', 'HTML'),
        ('app.js.orig', 'const x = 1;\n', 'JavaScript'),
        ('settings.py.bak', 'x = 1\n', 'Python'),
        ('config.yml.local', 'password: Xk9mQ2vLp4Rt\n', 'YAML'),
        ('setup.cfg.in', '[metadata]\nname = x\n', 'INI'),
        # wrappers on wrappers
        ('settings.yml.example.bak', 'password: Xk9mQ2vLp4Rt\n', 'YAML'),
        # without an extension under it, a file keeps the one it has
        ('page.tpl', '{$name}\n', 'Smarty'),
        ('Makefile.in', 'all:\n\techo x\n', 'Makefile'),
    ],
)
def test_a_wrapper_suffix_is_unwrapped(tmp_path, name, content, lexer):
    assert find(tmp_path, name, content) == lexer


def test_lexer_selection_is_unchanged_elsewhere(tmp_path):
    assert find(tmp_path, 'a.Rd', '\\name{x}\n') == 'S'  # Rd stays a case-sensitive meta extension (the R swap)
    assert find(tmp_path, 'a.rd', '\\name{x}\n') == 'Rd'
    assert find(tmp_path, 'settings.py', 'x = 1\n') == 'Python'
    assert find(tmp_path, 'notes.local', 'x\n') is None
    # user-interface markup: its attributes are look-alikes, and lexing it is slow
    assert find(tmp_path, 'Main.xaml', '<Window Title="x"/>\n') is None
    # Eclipse launch configurations: their `key` attributes hold setting names, never values
    assert find(tmp_path, 'debug.launch', '<booleanAttribute key="org.eclipse.debug.core.x" value="false"/>\n') is None
    # a file built with an explicit extension (an embedded region) keeps it
    assert LexerFinder().find(File(path=None, content='a: 1\n', extension='yaml')).name == 'YAML'
