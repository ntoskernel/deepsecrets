"""Value shapes: file names and paths, versions, and what must never count as either. Values are synthetic."""

import time

import pytest

from deepsecrets.core.helpers.value_shape import FILE_NAME, VERSION, value_shape


@pytest.mark.parametrize(
    'value',
    [
        'main.log',
        'logo.png',
        'IMG_2041.JPG',
        'q3.parquet',
        'terraform.tfstate',
        'archive.7z',
        'report.final.pdf',
        '/srv/tls/server.key',
        'C:\\certs\\client.pfx',
        'backups/billing-billingdb-solution-x7k2p/main.log',
        '.config/app/settings.json',
    ],
)
def test_file_names_and_paths(value):
    assert value_shape(value) == FILE_NAME


@pytest.mark.parametrize('value', ['3.0.17', '2.14.1-rc1', 'v1.22.3', 'postgres-13.2.1', 'release_2026.09.28'])
def test_versions(value):
    assert value_shape(value) == VERSION


def test_an_object_key_in_a_log_is_both():
    # the report that led to 2.2.1: an object key with a version in its directory name, reported at confidence 6
    assert value_shape('disk-diskurls-solution-backup-3.0.17-jpss9/main.log') == f'{FILE_NAME} {VERSION}'


@pytest.mark.parametrize(
    'value',
    [
        # random secrets have no dot, and dotted tokens end in a long mixed-case random part
        'R4nd0mT0k3nWithoutAnyDotsAtAll29',
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        'MTk4NjIyNDgzNDcxOTI1MjQ4.Cl2FMQ.ZnCjm1XVW7vRze4b7Cq4se7kKWs',
        'hvs.CAESIJx3Nf2p7kQm9WvYtR8sLdE4bGh1aZ',
        'pk.eyJ1IjoiZXhhbXBsZSIsImEiOiJjazEyMyJ9.Yq3n7Lm2Pw9sKd8fJx4Q1A',
        # an extension that is mixed case or too long is a random part, not an extension
        'abc.DefGhi',
        'name.abcdefghijk',
        # URLs and addresses are judged as they are
        'https://cdn.example.com/static/logo.png',
        'https://repo.example.com/pkg-3.0.17.tar.gz',
        'deploy@build-3.0.17.example.com',
        # a connection string ends in a host, not a file
        'DefaultEndpointsProtocol=https;AccountName=x;AccountKey=Zm9vYmFy/YmF6cXV4==;EndpointSuffix=core.windows.net',
        'token=Qx7Rt2Lm/abc.json',
        # whitespace: a PGP block with a Version header, prose
        '-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: 2.0.22\n\nlQOYBF...',
        'see main.log for details',
        # an IP address has four numbers, two numbers are not a version
        '10.0.0.1',
        '192.168.10.200',
        '0.75',
        # no dot at all
        'version_3_0_17',
    ],
)
def test_not_a_file_name_or_a_version(value):
    assert value_shape(value) == ''


def test_a_long_value_is_cheap():
    # 2.2.1 measured about 2 us per variable; a pathological dotted value must stay linear
    value = 'a.' * 50_000 + 'Ab'
    started = time.perf_counter()
    assert value_shape(value) == ''
    assert time.perf_counter() - started < 0.5
