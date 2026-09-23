"""The diagnostic replay names the stage where a value was lost, or what reported it. Values are synthetic."""

import json

import pytest

from deepsecrets.diagnostics.__main__ import main
from deepsecrets.diagnostics.trace import Rulesets, trace_file

TOKEN = 'Hk3vQ9ZpL2mXw7RtYb4NcF8aZ'
SOURCE = 'password = "T7r$kq92LmZx"\n' f'# key: {TOKEN}\n' f'client = Client("{TOKEN}")\n' f'session_id = "{TOKEN}"\n'


def case(case_id, line, value):
    text = SOURCE.split('\n')[line - 1]
    col = text.index(value) + 1
    return dict(case_id=case_id, line=line, end_line=line, start_col=col, end_col=col + len(value), value=value)


@pytest.fixture()
def traces(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(SOURCE)
    cases = [case('pw', 1, 'T7r$kq92LmZx'), case('comment', 2, TOKEN), case('ctor', 3, TOKEN), case('sess', 4, TOKEN)]
    return {t['case_id']: t for t in trace_file(str(path), 'src/settings.py', cases)}


def test_reported_value_names_its_engine_and_rule(traces):
    t = traces['pw']
    assert t['verdict'] == {'stage': 'reported', 'component': 'semantic_engine', 'detail': 'S105'}
    evaluation = t['evaluations'][0]
    assert evaluation['dangerous'] is True
    # counterfactual: the finding stands on one naming rule
    assert evaluation['dangerous_without'] == {'SEM_VAR_HIGH_CONFIDENCE_FULLNAME_2': False}


def test_secret_in_a_comment_is_lost_at_detection(traces):
    t = traces['comment']
    assert t['verdict']['stage'] == 'detection' and t['verdict']['detail'] == 'in a comment'
    assert t['token']['in_comment'] is True


def test_constructor_argument_is_not_a_variable(traces):
    t = traces['ctor']
    assert t['verdict'] == {
        'stage': 'detection',
        'component': 'variable_detection',
        'detail': 'no detection rule matched',
    }
    assert t['token']['window'].endswith('p[L]p⏎n')


def test_red_flag_name_is_rejected_by_the_evaluator(traces):
    t = traces['sess']
    assert t['verdict']['stage'] == 'evaluation'
    assert {'SEM_VAR_NAME_SLICE_REDFLAGS', 'SEM_VAR_NONSECRET_LAST_SLICE'} <= {
        r['id'] for r in t['evaluations'][0]['rules']
    }


def test_value_not_where_the_label_points(tmp_path):
    path = tmp_path / 'a.py'
    path.write_text(SOURCE)
    moved = dict(case('x', 1, 'T7r$kq92LmZx'), line=3, end_line=3)
    [t] = trace_file(str(path), 'a.py', [moved])
    assert t['located'] is False


def test_excluded_path_stops_the_replay_unless_exclusions_are_off(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(SOURCE)
    # a value nothing reports: only then does the verdict fall through to the selection stage
    cases = [case('ctor', 3, TOKEN)]
    vendored = 'node_modules/pkg/settings.py'
    [stopped] = trace_file(str(path), vendored, cases)
    assert stopped['verdict'] == {
        'stage': 'selection',
        'component': 'excluded_paths',
        'detail': '.*node_modules\\/.*',
    }
    # a scan run with --excluded-paths disable reads the file, so the replay has to as well, and then the verdict
    # names the stage that really lost the value
    [replayed] = trace_file(str(path), vendored, cases, Rulesets.builtin(path_exclusions=False))
    assert replayed['verdict'] == {
        'stage': 'detection',
        'component': 'variable_detection',
        'detail': 'no detection rule matched',
    }


def test_cli_replays_excluded_paths_on_request(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(SOURCE)
    cases = tmp_path / 'cases.jsonl'
    cases.write_text(
        json.dumps(dict(case('ctor', 3, TOKEN), path=str(path), relative_path='node_modules/p/settings.py'))
    )
    out = tmp_path / 'traces.jsonl'
    assert main(['trace', '--cases', str(cases), '--out', str(out)]) == 0
    assert json.loads(out.read_text())['verdict']['stage'] == 'selection'
    assert main(['trace', '--cases', str(cases), '--out', str(out), '--no-path-exclusions']) == 0
    assert json.loads(out.read_text())['verdict']['stage'] == 'detection'


def test_cli_writes_one_trace_per_case(tmp_path):
    path = tmp_path / 'settings.py'
    path.write_text(SOURCE)
    cases = tmp_path / 'cases.jsonl'
    cases.write_text(
        '\n'.join(
            json.dumps(dict(case(i, line, v), path=str(path), relative_path='settings.py'))
            for i, line, v in (('a', 1, 'T7r$kq92LmZx'), ('b', 4, TOKEN))
        )
    )
    out = tmp_path / 'traces.jsonl'
    assert main(['trace', '--cases', str(cases), '--out', str(out)]) == 0
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert sorted(t['case_id'] for t in lines) == ['a', 'b']


def test_cli_with_a_process_pool(tmp_path):
    # spawn children never re-import a package's __main__.py: the pool workers must live in an importable module
    paths = []
    for i in range(3):
        path = tmp_path / f'settings_{i}.py'
        path.write_text(SOURCE)
        paths.append(path)
    cases = tmp_path / 'cases.jsonl'
    cases.write_text(
        '\n'.join(
            json.dumps(dict(case(f'c{i}', 1, 'T7r$kq92LmZx'), path=str(p), relative_path=p.name))
            for i, p in enumerate(paths)
        )
    )
    out = tmp_path / 'traces.jsonl'
    assert main(['trace', '--cases', str(cases), '--out', str(out), '--processes', '2']) == 0
    verdicts = {
        json.loads(line)['case_id']: json.loads(line)['verdict']['stage'] for line in out.read_text().splitlines()
    }
    assert verdicts == {'c0': 'reported', 'c1': 'reported', 'c2': 'reported'}
