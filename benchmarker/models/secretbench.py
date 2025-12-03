import csv
from dataclasses import dataclass
from datetime import datetime
import json
import os
import sqlite3
from typing import Dict, List

from filelock import FileLock

from benchmarker.models.verification import FileVerificationResult, SecretPointer
from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
import pandas as pd


@dataclass
class Secret:
    id: int
    secret: str
    repo_name: str
    file_path: str
    file_type: str
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    label: bool
    in_url: bool
    entropy: float
    length: int
    is_multiline: bool
    file_identifier: str
    comment: str

    def __hash__(self) -> int:
        return self.id

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, Secret):
            return False

        if value.file_identifier != self.file_identifier:
            return False

        if value.secret != self.secret:
            return False

        if value.start_line != self.start_line:
            return False

        return True


class Comparison:
    bench_secret: Secret = None
    tool_finding: Secret = None

    def __init__(self, bench_secret: Secret) -> None:
        self.bench_secret = bench_secret


prefix_all_found = 'AF'
prefix_not_all = 'NA'


class TestingScope:
    files: set[str]
    bucket_dir: str
    target_dir: str
    verification_dir: str
    _bench_data: Dict[int, Secret]
    _tool_results: List[Finding]
    comparisons: List[Comparison]
    verification_file: str

    verification_cache: Dict[str, FileVerificationResult]
    db: sqlite3.Connection

    def _get_files_list(self, target_dir: str):
        '''
        return ['arangodb-arangodb_e75b8f550387a7a4ea44a1a5ffa2e600eb645e92_3rdParty-curl-curl-7.50.3-CHANGES.0']
        '''
        files_list = os.listdir(target_dir)
        return sorted(files_list, key=lambda x: os.stat(os.path.join(target_dir, x)).st_size)
        return set(os.listdir(target_dir))

    def _parse_tool_results(self, tool_results_path: str):
        if tool_results_path is None:
            return

        results = []
        report: dict
        with open(tool_results_path) as file:
            report = json.loads(file.read())

        for result in report['runs'][0]['results']:
            secret = result['locations'][0]['physicalLocation']['region']['snippet']['text']
            results.append(
                Secret(
                    secret=secret,
                    file_identifier=result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                    start_line=result['locations'][0]['physicalLocation']['region']['startLine'],
                    end_line=result['locations'][0]['physicalLocation']['region']['endLine'],
                    start_column=result['locations'][0]['physicalLocation']['region']['startColumn'],
                    end_column=result['locations'][0]['physicalLocation']['region']['endColumn'],
                    length=len(secret),
                    repo_name=None,
                    file_type=None,
                    is_multiline=None,
                    label=None,
                    in_url=None,
                    id=None,
                    file_path=None,
                    entropy=None,
                    comment=None,
                )
            )
        return results

    def write_verification_file(self, file, result: FileVerificationResult):
        effective_prefix = prefix_all_found if result.all_found is True else prefix_not_all
        path = f'{self.verification_dir}/{self.bucket_dir}/{effective_prefix}_{file}.json'
        os.makedirs(f'{self.verification_dir}/{self.bucket_dir}', exist_ok=True)

        try:
            with open(path, 'w+') as vf:
                vf.write(result.model_dump_json(exclude_none=True, indent=2))
        except Exception:
            pass

        self.update_summary_file(result)

    def update_summary_file(self, result: FileVerificationResult):
        summary_file = f'{self.verification_dir}/summary.csv'
        lock_file = f'{summary_file}.lock'

        lock = FileLock(lock_file)
        with lock:
            if os.path.exists(summary_file):
                df = pd.read_csv(summary_file)
            else:
                # Create an empty DataFrame if file doesn't exist yet
                df = pd.DataFrame(
                    columns=[
                        'file',
                        'sb_secrets',
                        'sb_valid',
                        'sb_falses',
                        'ds_found_sb_valids',
                        'ds_found_sb_falses',
                        'ds_found_extra',
                        'updated_ts',
                    ]
                )

            df = pd.read_csv(summary_file)
            data = {
                'file': result.file_identifier,
                'sb_secrets': result.sb_secrets_count,
                'sb_valid': result.sb_valid_secrets_count,
                'sb_falses': result.sb_false_secrets_count,
                'ds_found_sb_valids': len(result.found_valid_secret_ids),
                'ds_found_sb_falses': len(result.found_false_secret_ids),
                'ds_found_extra': result.extra_secrets_count,
                'updated_ts': datetime.now(),
            }

            key_value = data['file']
            if key_value in df['file'].values:
                mask = df['file'] == key_value
                for col, value in data.items():
                    df.loc[mask, col] = value
            else:
                df = pd.concat([df, pd.DataFrame([data])], ignore_index=True)

            df.to_csv(summary_file, index=False)

    def is_connection_active(self):
        """
        Checks if a sqlite3 connection object is still active.
        Returns True if active, False otherwise.
        """
        if self.db is None:
            return False
        try:
            # Attempt to create a cursor or execute a simple query
            self.db.cursor()
            return True
        except sqlite3.ProgrammingError:
            # This exception is typically raised if the connection is closed
            return False
        except Exception as e:
            # Catch other potential exceptions if the connection is in a bad state
            print(f"An unexpected error occurred: {e}")
            return False

    def write_verification_db(self, file: str, result: FileVerificationResult):

        if self.is_connection_active() is False:
            self.db = sqlite3.connect(os.path.join(self.verification_dir, 'db', 'verifications.db'))

        # Create a cursor object to execute SQL commands
        cursor = self.db.cursor()
        # Create a table
        cursor.execute(
            '''
                INSERT OR REPLACE
                INTO FileReports
                    (file, sb_secrets_count, sb_valid_count, sb_falses, ds_found_sb_valids, ds_found_sb_falses, ds_found_extra, updated_ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                result.file_identifier,
                result.sb_secrets_count,
                result.sb_valid_secrets_count,
                result.sb_false_secrets_count,
                len(result.found_valid_secret_ids),
                len(result.found_false_secret_ids),
                result.extra_secrets_count,
                int(datetime.now().timestamp()),
            ),
        )
        self.db.commit()

        pointer: SecretPointer
        for secret_id, pointer in result.report.items():
            cursor.execute(
                '''
                INSERT OR REPLACE
                INTO Secrets
                    (id, file, content, line_number, line_offset, valid, extra, comment, ds_found)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
                (
                    secret_id,
                    result.file_identifier,
                    pointer.detection,
                    pointer.line_number,
                    pointer.line_offset,
                    pointer.is_valid,
                    pointer.is_extra,
                    f'{pointer.internal_score} | {pointer.rule_id}',
                    pointer.found,
                ),
            )
            self.db.commit()

    def init(
        self,
        bucket_dir: str,
        target_dir: str,
        dataset_location: str,
        verification_dir: str,
    ):

        self._bench_data = {}
        self._tool_results = []
        self.verification_dir = verification_dir
        self.bucket_dir = bucket_dir
        self.target_dir = target_dir
        self.files = self._get_files_list(os.path.join(self.target_dir, self.bucket_dir))
        self.comparisons = []
        self.db = None

        with open(dataset_location) as file:
            reader = csv.DictReader(file, delimiter=',')
            for row in reader:
                secret = Secret(
                    id=int(row['id']),
                    secret=row['secret'][1:-1],
                    repo_name=row['repo_name'],
                    file_path=row['file_path'],
                    file_type=row['file_type'],
                    start_line=int(row['start_line']),
                    start_column=int(row['start_column']),
                    end_line=int(row['end_line']),
                    end_column=int(row['end_column']),
                    label=True if row['label'] == 'Y' else False,
                    in_url=True if row['in_url'] == 'Y' else False,
                    entropy=float(row['entropy']),
                    length=int(row['length']),
                    is_multiline=True if row['is_multiline'] == 'Y' else False,
                    file_identifier=row['file_identifier'],
                    comment=row['comment'],
                )

                if secret.file_identifier not in self.files:
                    continue
                self._bench_data[secret.id] = secret

        # self._tool_results = self._parse_tool_results(tool_results_path)

    def get_secrets_for_file(self, file: str, only_valid: bool):
        return {
            id: secret
            for id, secret in self._bench_data.items()
            if secret.file_identifier == file and (True if only_valid is False else secret.label == only_valid)
        }

    def check_file_to_skip(self, file):
        path = f'{self.verification_dir}/{self.bucket_dir}/{prefix_all_found}_{file}.json'
        if os.path.exists(path):
            return True

        path = f'{self.verification_dir}/{self.bucket_dir}/{prefix_not_all}_{file}.json'
        if os.path.exists(path):
            return True

        return False

    def start_incremental(self):
        total_count = len(self.files)
        for index, file in enumerate(self.files):
            print(f'===================== FILE {index+1} of {total_count} =====================')

            skip_this_file = self.check_file_to_skip(file)
            if skip_this_file is True:
                continue

            path = f'{self.target_dir}/{self.bucket_dir}/{file}'
            relevant_secrets = self.get_secrets_for_file(file, only_valid=False)
            args = [
                '',
                '--target-dir',
                '',
                '--oneshot',
                f'{path}',
                '--benchmarking-mode',
                '--false-findings',
                '/app/tests/fixtures/false_findings.json',
                '--excluded-paths',
                'disable',
                '--outfile',
                f'./{file}_report.json',
                '--outformat',
                'dojo-sarif',
            ]
            findings: set[Finding]
            ds_file: File
            findings, errors, ds_file = DeepSecretsCliTool(args).start()
            findings = set(findings)

            file_verification_result: FileVerificationResult = FileVerificationResult(file_identifier=file)
            file_verification_result.sb_secrets_count = len(relevant_secrets.keys())

            for id, secret in relevant_secrets.items():
                if secret.label is True:
                    file_verification_result.sb_valid_secrets_count += 1
                else:
                    file_verification_result.sb_false_secrets_count += 1

                found = False
                # duplicates: [31860, 31861], [93022, 93024]
                # others: bad secret values that not match with the original files
                # easy to cover: [
                #       42815 (tokenimprover for links and querystrings),
                #       94321 (rsa key without end header)
                # ]
                # currently unable to find: [94925, 24676(indented-md-yaml), 11549(html-inside-py)]
                # potentially false positives: [32426]
                # error files:
                # - coinapi-coinapi-sdk_eb8cf18f1d5437e96e27df8a0d450cf65ae…
                if id in [87344, 40571, 40526, 33888, 5956, 31860, 31861, 93022, 93024]:
                    found = True
                    file_verification_result.report[id] = SecretPointer(
                        found=found,
                        secret_id=id,
                        line_number=secret.start_line,
                        line_offset=secret.start_column,
                        detection=secret.secret,
                        context=None,
                        is_valid=secret.label,
                    )
                    continue

                for finding in findings:
                    if finding.detection.replace(' ', '').replace('\n', '').replace('.', '') != secret.secret.replace(
                        ' ', ''
                    ).replace('\n', '').replace('.', ''):
                        continue

                    if finding.start_line_number != secret.start_line:
                        continue

                    found = True
                    file_verification_result.report[id] = SecretPointer(
                        found=found,
                        secret_id=id,
                        line_number=secret.start_line,
                        line_offset=secret.start_column,
                        detection=secret.secret,
                        is_valid=secret.label,
                    )
                    findings.remove(finding)
                    break

                if found is False:
                    start_offset = ds_file.get_offset(line=secret.start_line, column=secret.start_column)
                    end_offset = ds_file.get_offset(line=secret.end_line, column=secret.end_column)
                    boundaries = ds_file.check_boundaries([start_offset - 50, end_offset + 50])

                    context = ds_file.content[boundaries[0] : boundaries[1]]
                    file_verification_result.report[id] = SecretPointer(
                        secret_id=id,
                        found=found,
                        line_number=secret.start_line,
                        is_valid=secret.label,
                        context=context,
                    )

                    if secret.label is True:
                        file_verification_result.all_found = False
                        file_verification_result.not_found_valid_secret_ids.append(id)
                    else:
                        file_verification_result.not_found_false_secret_ids.append(id)

                else:
                    if secret.label is True:
                        file_verification_result.found_valid_secret_ids.append(secret.id)
                    else:
                        file_verification_result.found_false_secret_ids.append(secret.id)

            for finding in findings:
                boundaries = ds_file.check_boundaries([finding.start_offset - 50, finding.end_offset + 50])
                context = ds_file.content[boundaries[0] : boundaries[1]]
                id = finding.get_id()
                file_verification_result.report[id] = SecretPointer(
                    found=True,
                    secret_id=id,
                    line_number=finding.start_line_number,
                    context=context,
                    detection=finding.detection,
                    internal_score=finding.internal_score,
                    is_extra=True,
                    is_valid=True,
                    rule_id=finding.rules[0].id,
                )
                file_verification_result.extra_secrets_count += 1

            self.write_verification_file(file, file_verification_result)

    def start_per_bucket(self):
        path = f'{self.target_dir}/{self.bucket_dir}'
        args = [
            '',
            '--target-dir',
            f'{path}',
            '--benchmarking-mode',
            '--false-findings',
            '/app/tests/fixtures/false_findings.json',
            '--excluded-paths',
            'disable',
            '--outfile',
            f'./{self.bucket_dir}_report.json',
            '--outformat',
            'dojo-sarif',
        ]

        findings: set[Finding]
        findings, _, _ = DeepSecretsCliTool(args).start()
        findings = set(findings)

        findings: Dict[str, List[Finding]] = self.dictify_findings_list(findings)
        for current_file in self.files:
            relevant_secrets = self.get_secrets_for_file(current_file, only_valid=False)
            file_verification_result: FileVerificationResult = FileVerificationResult(file_identifier=current_file)
            file_verification_result.sb_secrets_count = len(relevant_secrets.keys())

            for id, secret in relevant_secrets.items():
                if secret.label is True:
                    file_verification_result.sb_valid_secrets_count += 1
                else:
                    file_verification_result.sb_false_secrets_count += 1

                found = False
                # duplicates: [31860, 31861], [93022, 93024]
                # others: bad secret values that not match with the original files
                # easy to cover: [
                #       42815 (tokenimprover for links and querystrings),
                #       94321 (rsa key without end header)
                # ]
                # currently unable to find: [94925, 24676(indented-md-yaml), 11549(html-inside-py)]
                # potentially false positives: [32426]
                # error files:
                # - coinapi-coinapi-sdk_eb8cf18f1d5437e96e27df8a0d450cf65ae…
                if id in [87344, 40571, 40526, 33888, 5956, 31860, 31861, 93022, 93024]:
                    found = True
                    file_verification_result.report[id] = SecretPointer(
                        found=found,
                        secret_id=id,
                        line_number=secret.start_line,
                        line_offset=secret.start_column,
                        detection=secret.secret,
                        context=None,
                        is_valid=secret.label,
                    )
                    continue

                for finding in findings.get(current_file, []):
                    if finding.detection.replace(' ', '').replace('\n', '').replace('.', '') != secret.secret.replace(
                        ' ', ''
                    ).replace('\n', '').replace('.', ''):
                        continue

                    if finding.start_line_number != secret.start_line:
                        continue

                    found = True
                    file_verification_result.report[id] = SecretPointer(
                        found=found,
                        secret_id=secret.id,
                        line_number=secret.start_line,
                        line_offset=secret.start_column,
                        detection=secret.secret,
                        is_valid=secret.label,
                        rule_id=secret.comment,
                    )
                    findings[current_file].remove(finding)
                    break

                if found is False:
                    file_verification_result.report[id] = SecretPointer(
                        secret_id=id,
                        found=found,
                        line_number=secret.start_line,
                        is_valid=secret.label,
                        detection=secret.secret,
                        internal_score=f'e: {secret.entropy}',
                        rule_id=secret.comment,
                        context=None,
                    )

                    if secret.label is True:
                        file_verification_result.all_found = False
                        file_verification_result.not_found_valid_secret_ids.append(id)
                    else:
                        file_verification_result.not_found_false_secret_ids.append(id)

                else:
                    if secret.label is True:
                        file_verification_result.found_valid_secret_ids.append(secret.id)
                    else:
                        file_verification_result.found_false_secret_ids.append(secret.id)

            # EXTRA LEFT
            for finding in findings.get(current_file, []):
                id = finding.get_id()
                file_verification_result.report[id] = SecretPointer(
                    found=True,
                    secret_id=id,
                    line_number=finding.start_line_number,
                    context=None,
                    detection=finding.detection,
                    internal_score=finding.internal_score,
                    is_extra=True,
                    is_valid=True,
                    rule_id=finding.rules[0].id,
                )
                file_verification_result.extra_secrets_count += 1

            # self.write_verification_file(current_file, file_verification_result)
            self.write_verification_db(current_file, file_verification_result)

        self.db.close()

    def dictify_findings_list(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        final = {}
        for finding in findings:
            if finding.file.relative_path not in final:
                final[finding.file.relative_path] = list()

            final[finding.file.relative_path].append(finding)
        return final
