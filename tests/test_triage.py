import pytest

from siemx.triage import command_of, complexity, split_stages


@pytest.mark.parametrize("spl, expected", [
    ("index=a | stats count by host | head 5",
     ["index=a", "stats count by host", "head 5"]),
    ('index=a "x|y" | head 5', ['index=a "x|y"', "head 5"]),
    ("index=a 'x|y' | head 5", ["index=a 'x|y'", "head 5"]),
    ("index=a [ search b | head 1 ] | head 5",
     ["index=a [ search b | head 1 ]", "head 5"]),
    ("index=a [ search b [ search c | head 1 ] | head 2 ] | head 5",
     ["index=a [ search b [ search c | head 1 ] | head 2 ]", "head 5"]),
    ("index=a \"it's|x\" | head 5", ["index=a \"it's|x\"", "head 5"]),
    ("index=a ||  | head 5", ["index=a", "head 5"]),   # empty stages dropped
    ("  index=a  |  head 5  ", ["index=a", "head 5"]),  # whitespace trimmed
    ("index=a", ["index=a"]),
    ("", []),
])
def test_split_stages(spl, expected):
    assert split_stages(spl) == expected


def test_split_stages_multiline():
    spl = "index=a\n| stats count by host\n| sort - count"
    assert split_stages(spl) == ["index=a", "stats count by host", "sort - count"]


@pytest.mark.parametrize("stage, cmd", [
    ("stats count", "stats"),
    ("  STATS count", "stats"),
    ("head", "head"),
    ("", ""),
    ("| x", ""),
])
def test_command_of(stage, cmd):
    assert command_of(stage) == cmd


@pytest.mark.parametrize("spl, level", [
    ("index=a | stats count by host", "simple"),
    ("index=a | eval x=1", "medium"),
    ("index=a | rex field=_raw \"(?<u>\\w+)\"", "medium"),
    ("index=a | transaction host", "hard"),
    ("index=a [ search b | fields host ]", "hard"),
    ("index=stats", "simple"),  # first stage is the base search, not a command
])
def test_complexity(spl, level):
    assert complexity(spl) == level
