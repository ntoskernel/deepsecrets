from aenum import MultiValueEnum


class Language(MultiValueEnum):
    PYTHON = 'py'
    GOLANG = 'go'
    PHP = 'php'
    JS = 'js', 'jsx'
    TOML = 'toml'
    JSON = 'json'
    YAML = 'yaml'
    INI = 'ini'
    PUPPET = 'pp'
    SHELL = 'sh'
    CSHARP = 'cs'
    JAVA = 'java'
    KOTLIN = 'kt'
    SWIFT = 'swift'
    MARKDOWN = 'md'
    XML = 'xml'
    HTML = 'html'
    R = 'r'
    NIX = 'nix'
    RUBY = 'rb'
    # Pygments' Docker lexer: its first file name pattern is Dockerfile, its aliases docker and dockerfile
    DOCKER = 'Dockerfile', 'docker', 'dockerfile'

    ANY = 'any'
    UNKNOWN = 'unknown'

    @classmethod
    def from_text(cls, text: str) -> object:
        ext = text.split('.')[-1]
        return cls(ext)

    @classmethod
    def _missing_(cls, value: str) -> object:
        return Language.UNKNOWN
