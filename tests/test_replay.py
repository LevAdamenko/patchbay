import json

import pytest

from patchbay.clients import replay


def test_key_is_stable_across_dictionary_order():
    assert replay.key("x", {"b": 2, "a": 1}) == replay.key("x", {"a": 1, "b": 2})


def test_missing_fixture_names_expected_file(tmp_path):
    with pytest.raises(replay.FixtureMissing, match="thing-") as error:
        replay.load(tmp_path, "thing", {"query": "missing"})
    assert str(tmp_path) in str(error.value)


def test_saved_fixture_scrubs_keys_and_authorization(tmp_path):
    path = replay.save(
        tmp_path,
        "thing",
        {"headers": {"Authorization": "Bearer no"}, "api_key": "no", "value": 1},
        {"nested": {"NEBIUS_API_KEY": "no"}, "ok": True},
    )
    contents = path.read_text()
    assert "Authorization" not in contents
    assert "api_key" not in contents
    assert "no\"" not in contents
    assert json.loads(contents)["request"] == {"headers": {}, "value": 1}


def test_key_ignores_pytest_durations_and_sandbox_dirs():
    def feedback(log: str) -> dict:
        return {"messages": [{"role": "user", "content": f"Test rejected.\nLast 2000 chars of test log:\n{log}"}]}

    recorded = feedback("/tmp/patchbay-sandbox-k2j3h4_x/site/x.py:3\n1 passed in 0.02s\n")
    replayed = feedback("/tmp/patchbay-sandbox-a9b8c7d6/site/x.py:3\n1 passed in 0.03s\n")
    slow = feedback("/tmp/patchbay-sandbox-a9b8c7d6/site/x.py:3\n1 failed in 62.31s (0:01:02)\n")
    assert replay.key("nemotron", recorded) == replay.key("nemotron", replayed)
    assert replay.key("nemotron", slow) == replay.key(
        "nemotron", feedback("/tmp/patchbay-sandbox-zzzzzzzz/site/x.py:3\n1 failed in 1.0s\n")
    )
    # Outcomes still distinguish requests: only noise is ignored.
    assert replay.key("nemotron", recorded) != replay.key("nemotron", slow)


def test_key_ignores_object_addresses_in_tracebacks():
    def feedback(addr: str) -> dict:
        return {"messages": [{"role": "user", "content": f"E   AttributeError: <MagicMock id={addr}>"}]}

    assert replay.key("nemotron", feedback("0x7a05a28bef90")) == replay.key("nemotron", feedback("0x75f3bbe3de80"))
