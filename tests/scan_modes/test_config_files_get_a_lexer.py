"""2.3 (R1): configuration files that got no lexer are read now, end to end through a scan. The files are written to
tmp_path: a fixture named .env cannot be committed (KI-TEST-13), and the whole-tree fixture counts must not move.
Values are synthetic."""

import json

import pytest

from deepsecrets.cli import DeepSecretsCliTool

PASSWORD = 'Xk9mQ2vLp4RtBn7W'
TOKEN = 'Hk3vQ9ZpL2mXw7RtYb4NcF8a'
NPM_TOKEN = 'npm_Tq7XbR2mKp9LvZ4wNc8FjD3sHk3vQ9ZpL2mX'
NPM_UUID = '3f6b2c1e-8a4d-4f7b-9c2e-5d1a0b7e6f43'

FILES = {
    '.env': f'DB_PASSWORD={PASSWORD}\n',
    'deploy/prod.env': f'API_TOKEN={TOKEN}\n',
    '.env.production': f'DB_PASSWORD={PASSWORD}2\n',
    'web.config': f'<configuration><appSettings><add key="x" apiPassword="{PASSWORD}3"/></appSettings></configuration>\n',
    'Dockerfile': f'FROM python:3.11\nENV DB_PASSWORD={PASSWORD}4\nENV API_TOKEN {TOKEN}5\n',
    '.npmrc': f'//registry.npmjs.org/:_authToken={NPM_TOKEN}\n//npm.example.org/:_authToken={NPM_UUID}\n',
    'config/settings.yml.example': f'password: {PASSWORD}6\n',
}


@pytest.fixture(scope='module')
def report(tmp_path_factory):
    root = tmp_path_factory.mktemp('repo')
    for name, content in FILES.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content)
    outfile = tmp_path_factory.mktemp('out') / 'report.sarif'
    tool = DeepSecretsCliTool(
        args=['', '--target-dir', str(root), '--outfile', str(outfile), '--process-count', '1', '--disable-masking']
    )
    tool.start()
    found = {}
    for result in json.load(open(outfile))['runs'][0]['results']:
        location = result['locations'][0]['physicalLocation']
        found.setdefault(location['artifactLocation']['uri'], []).append(
            (result['ruleId'].split('-')[0], location['region']['snippet']['text'])
        )
    return found


@pytest.mark.parametrize(
    'path, rule, value',
    [
        ('.env', 'S105', PASSWORD),
        ('deploy/prod.env', 'S105', TOKEN),
        ('.env.production', 'S105', f'{PASSWORD}2'),
        ('web.config', 'S105', f'{PASSWORD}3'),
        ('Dockerfile', 'S105', f'{PASSWORD}4'),
        # the space form, a detection rule of the Docker language
        ('Dockerfile', 'S105', f'{TOKEN}5'),
        ('.npmrc', 'S57', NPM_TOKEN),
        ('.npmrc', 'S57', NPM_UUID),
        ('config/settings.yml.example', 'S105', f'{PASSWORD}6'),
    ],
)
def test_a_secret_in_a_config_file_is_reported(report, path, rule, value):
    assert (rule, value) in report.get(path, []), report.get(path)
