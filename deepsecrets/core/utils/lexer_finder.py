import os
from typing import Dict, Optional

from pygments import highlight

from deepsecrets.core.model.file import File
from deepsecrets.core.utils.guess_filetype import FileTypeGuesser
from pygments.lexers import get_lexer_for_filename, get_lexer_by_name
from pygments.util import ClassNotFound
from pygments.formatters import RawTokenFormatter
from pygments.lexers.special import RawTokenLexer

# Suffixes that wrap a file's real extension: settings.yml.example is YAML, index.html.tpl is HTML, .env.local is a .env
# file. Without an extension under it (page.tpl, Makefile.in), a file keeps the one it has
WRAPPER_SUFFIXES = frozenset({'example', 'sample', 'dist', 'template', 'tpl', 'orig', 'bak', 'local', 'in'})
# Extensions no Pygments lexer claims, and what the finder reads them as. 'xml' goes on to the guesser, whose HTML swap
# yields attributes (web.config's decryptionKey="...") as variables. Not .xaml: user-interface markup whose attributes
# are look-alikes, and which the HTML lexer reads about 50 times slower than no lexer (2 s for 100 KB), measured on the
# 3,000-file SecretBench sample. Not Eclipse's .launch: its `key` attributes hold setting names
# (`<booleanAttribute key="…" value="false"/>`), 11 units beyond SecretBench's labels and none of them a secret
EXTENSION_ALIASES = {
    'config': 'xml',
    'csproj': 'xml',
    'nuspec': 'xml',
    'wxs': 'xml',
    'props': 'xml',
    'targets': 'xml',
    'mdx': 'md',
    'rmd': 'md',
}
# NAME=VALUE configuration with no lexer of its own: the guesser reads it, and its sectionless-INI probe fits it. .env,
# x.env and every .env.* file, and these dotfiles
ENV_EXTENSION = 'env'
GUESSED_FILE_NAMES = frozenset({'.npmrc', '.pypirc', '.flaskenv'})
# Extensions the guesser decides: compared in lower case (.TXT, .Conf, .XML), except Rd, which Pygments' own Rd lexer
# claims in lower case
META_EXTENSIONS = frozenset({'txt', 'conf', 'cshtml', 'xml'})
CASE_SENSITIVE_META_EXTENSIONS = frozenset({'Rd'})
# Dockerfile and Dockerfile.* (Dockerfile.prod): the Docker lexer, before the guesser reads them as YAML
DOCKER = 'docker'


class LexerFinder:
    """Chooses the Pygments lexer for a file. The extension decides, as a Pygments alias and then with the file name
    against Pygments' file patterns; an extension of a format Pygments does not know is mapped first (the tables above),
    and a file without one, or of a meta format (txt, conf, xml...), is read by the content guesser (FileTypeGuesser).
    `find` returns None when nothing claims the file: then only the regex rules and the cheap search read it."""

    file: File
    extension: Optional[str]
    distinguishing_feature: Optional[str]

    alias_exceptions: Dict
    probes: Dict

    def __init__(self) -> None:
        # instance attributes, patched per instance where needed. No JSX lexer to load: Pygments' own JsxLexer answers
        # the jsx and react aliases (KI-TOK-18)
        self.alias_exceptions = {'js+react': 'react'}
        # content probes per extension, each giving a feature that refines the alias (js -> js+react)
        self.probes = {'js': [_probe_react]}

    def find(self, file: File):
        self.file = file
        self.extension = self._determine_extension()
        self.distinguishing_feature = self._determine_distinguishing_feature()

        try:
            return get_lexer_by_name(self._projected_alias())
        except ClassNotFound:
            pass
        try:
            return get_lexer_for_filename(self._projected_filename(), file.content)
        except ClassNotFound:
            return None

    def _determine_extension(self) -> Optional[str]:
        """The extension the lexer is chosen by: the file's own, unwrapped and mapped through the tables, or a guess."""
        base = os.path.basename(self.file.path) if self.file.path else ''
        if base.lower() == 'dockerfile' or base.lower().startswith('dockerfile.'):
            return DOCKER

        extension = self.file.extension
        if base and extension is not None and extension.lower() in WRAPPER_SUFFIXES:
            extension = unwrapped_extension(base)
        if extension is None:
            return self._try_guess_extension(None)
        if extension.lower() == ENV_EXTENSION or base.startswith('.env.') or base in GUESSED_FILE_NAMES:
            return self._try_guess_extension(extension)

        extension = EXTENSION_ALIASES.get(extension.lower(), extension)
        if extension.lower() in META_EXTENSIONS:
            return self._try_guess_extension(extension.lower())
        if extension in CASE_SENSITIVE_META_EXTENSIONS:
            return self._try_guess_extension(extension)
        return extension

    def _try_guess_extension(self, extension: Optional[str]) -> Optional[str]:
        guess = FileTypeGuesser().guess(name=self.file.name, extension=extension, content=self.file.content)
        if guess is not None:
            return guess
        # HOCON files are lexed well by the CoffeeScript lexer
        return self._if_hocon_coffeescript_hack()

    def _if_hocon_coffeescript_hack(self) -> Optional[str]:
        """'coffeescript' whenever the CoffeeScript lexer yields any token for the content (KI-TOK-10)."""
        try:
            rendered = highlight(self.file.content, get_lexer_by_name('coffeescript'), RawTokenFormatter())
            tokens = list(RawTokenLexer().get_tokens(rendered))
        except Exception:
            return None
        return 'coffeescript' if tokens else None

    def _determine_distinguishing_feature(self) -> Optional[str]:
        for probe in self.probes.get(self.extension, []):
            feature = probe(self.file)
            if feature is not None:
                return feature
        return None

    def _projected_alias(self) -> str:
        alias = self.extension or ''
        if self.distinguishing_feature is not None:
            alias = f'{alias}+{self.distinguishing_feature}'
        return self.alias_exceptions.get(alias, alias)

    def _projected_filename(self) -> str:
        return f'{self.file.name}.{self.extension}' if self.extension is not None else self.file.name


def unwrapped_extension(file_name: str) -> Optional[str]:
    """The extension under any wrapper suffixes (settings.yml.example: yml), else the file's last one; None for none.
    A dotfile's own name counts as its extension (.env: env), as File.extension has it."""
    parts = file_name.split('.')[1:]
    while len(parts) > 1 and parts[-1].lower() in WRAPPER_SUFFIXES:
        parts.pop()
    return parts[-1] if parts else None


def _probe_react(file: File):
    # very simple approach at the moment
    evidences = [
        'import React',
        'ReactDOM',
    ]
    if any(evidence in file.content for evidence in evidences):
        return 'react'
    return None
