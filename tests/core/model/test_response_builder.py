import pytest

from deepsecrets.core.model.response.base import BaseResponseBuilder


@pytest.fixture
def base_response_builder():
    return BaseResponseBuilder()


@pytest.mark.parametrize(
    "snippet, detection, expected",
    [
        (
            "hellomydearfriends",
            "hellomydearfriends",
            "hell*********iends",
        ),
        (
            "abcdefgh",
            "abcdefgh",
            "ab****gh",
        ),
        (
            "abcde",
            "abcde",
            "a***e",
        ),
        (
            "x",
            "x",
            "*",
        ),
        (
            "xy",
            "xy",
            "*y",
        ),
        (
            "xyz",
            "xyz",
            "**z",
        ),
        (
            "hello",
            "",
            "hello",
        ),
        (
            "error: secret_password_123 found",
            "secret_password_123",
            "error: secr**********d_123 found",
        ),
        (
            "token: 123456, old_token: 123456",
            "123456",
            "token: 1***56, old_token: 1***56",
        ),
        (
            "confidential: admin master 77",
            "admin master 77",
            "confidential: adm********r 77",
        ),
        (
            "hello world",
            "not_found",
            "hello world",
        ),
    ],
)
def test_masking(base_response_builder, snippet, detection, expected):
    assert base_response_builder._mask(snippet, detection) == expected
