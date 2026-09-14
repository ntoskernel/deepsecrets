from configparser import ConfigParser
import json
import tomllib
import yaml
import regex as re
from typing import Optional
from puppetparser.parser import parse

INI_KEY_VALUE_LINE = re.compile(r'^\s*[A-Za-z_][\w.\-]*\s*=.*$')
INI_SKIPPABLE_LINE = re.compile(r'^\s*(?:[#;].*)?$')


class FileTypeGuesser:

    def __init__(self) -> None:

        self.hot_swaps = {
            'Rd': 'R',
            'cshtml': 'html',
            'xml': 'html',  # TODO: Check https://github.com/pygments/pygments/issues/1785
        }

        # Order matters: the puppet and yaml parsers accept plain NAME=VALUE lines
        self.probes = {
            'json': self._is_json,
            'toml': self._is_toml,
            'ini': self._is_ini,
            'pp': self._is_puppet,
            'yaml': self._is_yaml,
            'rst': self._is_rst,
            # 'properties': self._dot_properties,
        }

    def guess(self, name: str, content: str, extension: Optional[str]) -> Optional[str]:

        swap = self.hot_swaps.get(extension)
        if swap is not None:
            return swap

        for ext, probe in self.probes.items():
            if probe(content):
                return ext

        # TODO: Guesslang
        # TODO: HOCON parser
        '''
        ml_guesser = Guess()
        guess = ml_guesser.language_name(content)
        if not guess:
            return None

        for ext, name in ml_guesser._extension_map.items():
            if name == guess:
                return ext
        '''
        return None

    def _is_json(self, content: str):
        try:
            json.loads(content)
        except Exception:
            return False

        return True

    def _is_toml(self, content: str):
        try:
            tomllib.loads(content)
        except Exception:
            return False

        return True

    def _is_yaml(self, content: str):
        try:
            _ = yaml.safe_load(content)
        except yaml.YAMLError:
            return False

        return True

    def _is_puppet(self, content: str):
        try:
            _, _ = parse(content)
        except Exception:
            return False

        return True

    def _is_ini(self, content):
        return self._is_sectionless_ini(content) or self._is_sectioned_ini(content)

    def _is_sectionless_ini(self, content: str):
        # ConfigParser requires a [section] header, so NAME=VALUE-only files are checked line by line
        lines = [line for line in content.splitlines() if not INI_SKIPPABLE_LINE.match(line)]
        return len(lines) > 0 and all(INI_KEY_VALUE_LINE.match(line) for line in lines)

    def _is_sectioned_ini(self, content: str):
        try:
            _ = ConfigParser().read_string(content)
        except Exception:
            return False
        return True

    def _is_rst(self, content: str):
        features = ['.. code-block::']
        for feature in features:
            if feature in content:
                return True
