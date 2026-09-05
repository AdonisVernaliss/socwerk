from __future__ import annotations

import pytest

from socwerk.query import QueryError, compile_query

from .test_scenarios import scenario_repository


def test_query_language_supports_comparison_contains_and_logic() -> None:
    events = scenario_repository().get("suspicious-powershell").events
    predicate = compile_query(
        'source = sysmon and (severity = high or contains(summary, "encoded"))'
    )
    assert [event.id for event in events if predicate(event)] == ["ps-003", "ps-004", "ps-008"]


def test_query_matches_list_membership() -> None:
    events = scenario_repository().get("suspicious-powershell").events
    predicate = compile_query("mitre = T1059.001")
    assert [event.id for event in events if predicate(event)] == ["ps-004", "ps-005", "ps-010"]
    identity = compile_query("user = usr-ops-402 and asset = asset-ws-402")
    assert len([event for event in events if identity(event)]) == 8


@pytest.mark.parametrize(
    "source",
    ["source ~~ sysmon", "contains(summary)", "source =", "(source = sysmon", "x = 1 trailing"],
)
def test_malformed_queries_are_rejected(source: str) -> None:
    with pytest.raises(QueryError):
        compile_query(source)


def test_query_length_is_bounded() -> None:
    with pytest.raises(QueryError, match="1000"):
        compile_query("x" * 1001)
