"""Checks for socbot's grouping, new-vs-known split, quiet-sender logic and report. Run: python3 -m pytest tests"""

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("socbot_report", REPO / "bots" / "socbot" / "report.py")
socbot = importlib.util.module_from_spec(spec)
sys.modules["socbot_report"] = socbot
spec.loader.exec_module(socbot)
NOW = 1_800_000_000.0


def alert(signature: str, severity: str = "high", observer: str = "fw1") -> dict:
    """One recent_alerts row, shaped like the live reply (SSDF wraps log-derived text)."""
    return {"event_id": "x", "timestamp": "2026-01-01 00:00:00.000", "provider": "juniper", "event_kind": "alert",
            "signature": {"value": signature, "truncated": False, "untrusted": True}, "severity": severity, "severity_num": 2,
            "source_ip": "198.51.100.7", "destination_ip": "192.0.2.58", "observer": observer}


def test_alerts_grouped_and_sorted_by_severity_then_count():
    rows = [alert("a"), alert("a"), alert("b", "critical"), alert("c", "low"), alert("a", observer="fw2")]
    groups = socbot.group_alerts(rows)
    assert [(g["signature"], g["observer"], g["count"]) for g in groups] == [("b", "fw1", 1), ("a", "fw1", 2), ("a", "fw2", 1), ("c", "fw1", 1)]


def test_new_known_forgotten_and_baseline():
    groups = socbot.group_alerts([alert("seen"), alert("old"), alert("fresh")])
    known = {"seen": NOW - 60, "old": NOW - socbot.FORGET_SECONDS - 1, "other": NOW - 60}
    new, known = socbot.classify_signatures(groups, known, NOW, False)
    assert new == {"old", "fresh"} and known["seen"] == NOW and known["other"] == NOW - 60
    new, known = socbot.classify_signatures(groups, {}, NOW, True)  # baseline learns without marking
    assert new == set() and set(known) == {"seen", "old", "fresh"}


def test_top_denied_counts():
    rows = [{"source_ip": "203.0.113.1", "destination_ip": "192.0.2.5"}, {"source_ip": "203.0.113.1", "destination_ip": "192.0.2.6"},
            {"source_ip": "203.0.113.2", "destination_ip": None}]
    assert socbot.top_denied(rows, "source_ip") == [("203.0.113.1", 2), ("203.0.113.2", 1)]
    assert socbot.top_denied(rows, "destination_ip") == [("192.0.2.5", 1), ("192.0.2.6", 1)]


def test_quiet_subjects_flagged_then_info():
    ingest = {"firewalls": [{"name": "fw1", "provider": "juniper", "hours_since": 5, "stale": True},
                            {"name": "off", "provider": "paloalto", "hours_since": 100, "stale": True},
                            {"name": "ok", "provider": "juniper", "hours_since": 0.1, "stale": False}]}
    fabric = {"subjects": [{"name": "unifi", "kind": "source", "signal": "s", "budget_hours": 0.5, "last_seen": None, "hours_since": None, "stale": True}]}
    recent, long_quiet = socbot.quiet_subjects(ingest, fabric)
    assert [line.split()[1] for line in recent] == ["fw1", "unifi"] and long_quiet == ["off"]


def test_report_quiet_day_and_findings():
    quiet = {"at": NOW, "baseline": False, "alerts": [], "new": [], "alerts_truncated": False, "denied_src": [], "denied_dst": [],
             "denied_total": 0, "denied_truncated": False,
             "ingest": {"firewalls": []}, "fabric": {"subjects": []}}
    assert "✅" in socbot.build_report(quiet)
    run = {**quiet, "alerts": socbot.group_alerts([alert("ET scan @everyone `x`")]), "new": ["ET scan @everyone `x`"],
           "denied_src": [("203.0.113.1", 7)], "denied_total": 7, "ingest": {"firewalls": [{"name": "fw9", "hours_since": 6, "stale": True}]}}
    text = socbot.build_report(run)
    assert "🆕 high ×1 fw1: ET scan @​everyone  x " in text and "Top denied sources (7 denies): 203.0.113.1 ×7" in text
    assert "🔇 fw9" in text and "✅" not in text
    assert "SSDF query failed" in socbot.build_report({"at": NOW, "error": "RuntimeError: forbidden"})


def test_error_reply_raises():
    try:
        socbot.checked("recent_alerts", {"error": "forbidden", "detail": "not permitted"})
        raise AssertionError("an error reply must not read as a quiet night")
    except RuntimeError as exc:
        assert "forbidden" in str(exc)


def test_collect_reads_live_shaped_replies():
    replies = {"recent_alerts": {"rows": [alert("N/A", "medium", "fw-edge")] * 2, "row_count": 2, "truncated": True},  # a short page: not a cut-off
               "query_flows": {"rows": [{"event_action": "flow_session_deny", "source_ip": "198.51.100.8", "destination_ip": "192.0.2.1"}],
                               "row_count": 1, "truncated": False},
               "ingest_status": {"firewalls": [], "summary": {}}, "fabric_status": {"subjects": [], "healthy": True}}
    calls = []
    run, known = socbot.collect(lambda tool, arguments: calls.append((tool, arguments)) or replies[tool], NOW, {}, False)
    assert [arguments.get("providers") for tool, arguments in calls if tool == "recent_alerts"] == list(socbot.ALERT_PROVIDERS)
    assert calls[-3][0] == "query_flows" and calls[-3][1]["action"] == "flow_session_deny"
    assert run["new"] == ["N/A"] and run["alerts"][0]["count"] == 6 and not run["alerts_truncated"] and run["denied_src"] == [("198.51.100.8", 1)] and "N/A" in known
