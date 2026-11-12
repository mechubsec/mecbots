"""Checks for socbot's grouping, new-vs-known split, quiet-sender logic and report. Run: python3 -m pytest tests"""

import importlib.util
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("socbot_report", REPO / "bots" / "socbot" / "report.py")
socbot = importlib.util.module_from_spec(spec)
sys.modules["socbot_report"] = socbot
spec.loader.exec_module(socbot)
NOW = 1_800_000_000.0


def wrapped(text: str) -> dict:
    """SSDF's wrapper for log-derived text."""
    return {"value": text, "truncated": False, "untrusted": True}


def alert(signature: str, severity: str = "high", observer: str = "fw1", count: int = 1, provider: str = "juniper") -> dict:
    """One alert_counts row, shaped like the live reply (SSDF wraps log-derived text)."""
    return {"provider": provider, "observer": wrapped(observer), "signature": wrapped(signature), "severity": severity,
            "severity_num": 2, "count": count, "first_seen": "2026-01-01 14:44:35.000", "last_seen": "2026-01-01 16:22:15.000"}


def test_alerts_grouped_and_sorted_by_severity_then_count():
    rows = [alert("a", count=1), alert("a", count=1, provider="paloalto"), alert("b", "critical"), alert("c", "low"), alert("a", observer="fw2")]
    groups = socbot.group_alerts(rows)  # same key from two providers is summed
    assert [(g["signature"], g["observer"], g["count"]) for g in groups] == [("b", "fw1", 1), ("a", "fw1", 2), ("a", "fw2", 1), ("c", "fw1", 1)]
    assert socbot.group_alerts([alert("big", count=10333)])[0]["count"] == 10333


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
             "denied_total": 0, "denied_truncated": False, "denied_unranked": 0,
             "ingest": {"firewalls": []}, "fabric": {"subjects": []}}
    assert "✅" in socbot.build_report(quiet)
    run = {**quiet, "alerts": socbot.group_alerts([alert("ET scan @everyone `x`")]), "new": ["ET scan @everyone `x`"],
           "denied_src": [("203.0.113.1", 7)], "denied_total": 7, "ingest": {"firewalls": [{"name": "fw9", "hours_since": 6, "stale": True}]}}
    text = socbot.build_report(run)
    assert "🆕 high ×1 fw1: ET scan @​everyone  x " in text and "Top denied sources: 203.0.113.1 ×7" in text
    assert "🔇 fw9" in text and "✅" not in text
    assert "SSDF query failed" in socbot.build_report({"at": NOW, "error": "RuntimeError: forbidden"})


def test_error_reply_raises():
    try:
        socbot.checked("alert_counts", {"error": "forbidden", "detail": "not permitted"})
        raise AssertionError("an error reply must not read as a quiet night")
    except RuntimeError as exc:
        assert "forbidden" in str(exc)


def test_collect_reads_live_shaped_replies():
    replies = {"alert_counts": {"rows": [alert("N/A", "medium", "fw-prod", count=2)], "row_count": 1, "truncated": False},
               "query_flows": {"rows": [{"event_action": "flow_session_deny", "source_ip": "198.51.100.8", "destination_ip": "192.0.2.1"}],
                               "row_count": 1, "truncated": False},
               "ingest_status": {"firewalls": [], "summary": {}}, "fabric_status": {"subjects": [], "healthy": True}}
    calls = []
    run, known = socbot.collect(lambda tool, arguments: calls.append((tool, arguments)) or replies[tool], NOW, {}, False)
    assert [(tool, arguments) for tool, arguments in calls if tool.endswith("alerts") or tool == "alert_counts"] == [
        ("alert_counts", {"since": "now-24h", "min_severity": "medium", "providers": ""})]  # one exact-count call, no recent_alerts
    assert [arguments["action"] for tool, arguments in calls if tool == "query_flows"] == list(socbot.DENY_ACTIONS)
    assert run["new"] == ["N/A"] and run["alerts"][0]["count"] == 2 and not run["alerts_truncated"] and run["denied_src"] == [("198.51.100.8", 3)] and "N/A" in known


def quiet_run(**changes) -> dict:
    """A run with nothing to report, overridden by changes."""
    return {"at": NOW, "baseline": False, "alerts": [], "new": [], "alerts_truncated": False, "denied_src": [], "denied_dst": [],
            "denied_total": 0, "denied_truncated": False, "denied_unranked": 0, "ingest": {"firewalls": []}, "fabric": {"subjects": []}, **changes}


def test_new_signature_below_the_top_ten_is_still_shown():
    groups = socbot.group_alerts([alert(f"sig{index}") for index in range(12)] + [alert("rare", "low")])
    text = socbot.build_report(quiet_run(alerts=groups, new=["rare"]))
    assert "🆕 low ×1 fw1: rare" in text and "+2 more groups" in text


def test_truncated_alert_counts_warn_and_exact_counts_do_not_say_floor():
    text = socbot.build_report(quiet_run(alerts_truncated=True))
    assert "500-group limit" in text and "✅" not in text
    exact = socbot.build_report(quiet_run(alerts=socbot.group_alerts([alert("a", count=10333)])))
    assert "Alerts: 10333 in 1 groups" in exact and "floor" not in exact and "capped" not in exact and "500" not in exact


def test_denies_without_ipv4_and_sampled_rankings_are_stated():
    text = socbot.build_report(quiet_run(denied_total=3000, denied_truncated=True, denied_unranked=2))
    assert "Denied flows: 3000 (rankings use only the newest" in text and "2 without an IPv4 address" in text and "✅" not in text


def test_collect_queries_every_deny_action_and_counts_unranked_ipv6():
    flows = {"flow_session_deny": {"rows": [{"source_ip": None, "destination_ip": None}], "row_count": 1, "truncated": False},
             "flow_deny": {"rows": [{"source_ip": "203.0.113.9", "destination_ip": "192.0.2.9"}], "row_count": 1, "truncated": True},
             "flow_drop": {"rows": [], "row_count": 0, "truncated": False}}
    empty = {"rows": [], "row_count": 0, "truncated": False}
    replies = {"alert_counts": {**empty, "truncated": True}, "ingest_status": {"firewalls": []}, "fabric_status": {"subjects": []}}
    call = lambda tool, arguments: flows[arguments["action"]] if tool == "query_flows" else replies[tool]
    run, _ = socbot.collect(call, NOW, {}, False)
    assert run["denied_total"] == 2 and run["denied_unranked"] == 1 and run["denied_truncated"] and run["alerts_truncated"]


# --- escalation to socagent ------------------------------------------------------------------------------

PREVIOUS = {"denied_total": 10, "logging": ["fw-a", "fw-b", "fw-c"]}


def esc_run(**changes) -> dict:
    """A non-baseline run with the fields escalations() reads, overridden by changes."""
    return quiet_run(**changes)


def kinds(items):
    return [item["kind"] for item in items]


def test_new_high_or_critical_alert_escalates_but_known_medium_and_baseline_do_not():
    groups = socbot.group_alerts([alert("fresh-high", "high"), alert("fresh-crit", "critical"), alert("fresh-med", "medium"), alert("old-high", "high")])
    items = socbot.escalations(esc_run(alerts=groups, new=["fresh-high", "fresh-crit", "fresh-med"]), PREVIOUS)
    assert [item["facts"]["signature"] for item in items] == ["fresh-crit", "fresh-high"]  # critical first; medium and known-high stay out
    assert items[0] == {"id": "1-new-high-alert", "kind": "new-high-alert", "summary": "new critical alert x1 on fw1: fresh-crit",
                        "facts": {"signature": "fresh-crit", "severity": "critical", "observer": "fw1", "count": 1}}
    assert socbot.escalations(esc_run(alerts=groups, new=["fresh-high"], baseline=True), PREVIOUS) == []  # the baseline night: everything is new
    assert socbot.escalations(esc_run(alerts=groups, new=["fresh-high"]), None) == []  # nothing to compare against


def test_deny_spike_needs_three_times_the_previous_total_and_at_least_100():
    spike = lambda total, before: kinds(socbot.escalations(esc_run(denied_total=total), {**PREVIOUS, "denied_total": before}))
    assert spike(300, 100) == ["deny-spike"] and spike(299, 100) == []  # exactly 3x fires, just under does not
    assert spike(99, 0) == [] and spike(100, 0) == ["deny-spike"]  # the floor of 100
    (item,) = socbot.escalations(esc_run(denied_total=500, denied_src=[("203.0.113.1", 400)], denied_dst=[("192.0.2.5", 300)]), PREVIOUS)
    assert item["facts"] == {"denied_total": 500, "previous_total": 10, "top_sources": [("203.0.113.1", 400)], "top_destinations": [("192.0.2.5", 300)]}


def test_firewall_quiet_only_when_it_was_logging_and_over_six_hours_but_not_long_quiet():
    firewalls = [{"name": "fw-a", "provider": "juniper", "hours_since": 7.4, "stale": True, "last_event": "2026-01-01T10:00:00"},  # fires
                 {"name": "fw-b", "provider": "juniper", "hours_since": 5.9, "stale": True},  # not over 6 h yet
                 {"name": "fw-c", "provider": "juniper", "hours_since": 60, "stale": True},  # long quiet: already an info line
                 {"name": "fw-x", "provider": "juniper", "hours_since": 9, "stale": True},  # was not logging at the previous run
                 {"name": "fw-ok", "provider": "juniper", "hours_since": 0.1, "stale": False}]
    (item,) = socbot.escalations(esc_run(ingest={"firewalls": firewalls}), PREVIOUS)
    assert item["kind"] == "firewall-quiet" and item["facts"] == {"firewall": "fw-a", "provider": "juniper", "hours_since": 7.4, "last_event": "2026-01-01T10:00:00"}
    assert socbot.snapshot(esc_run(denied_total=4, ingest={"firewalls": firewalls})) == {"denied_total": 4, "logging": ["fw-ok"]}


def test_queue_is_capped_at_three_and_ordered_alerts_then_spike_then_quiet():
    groups = socbot.group_alerts([alert(f"s{index}", "high") for index in range(4)])
    firewalls = [{"name": "fw-a", "hours_since": 8, "stale": True}]
    items = socbot.escalations(esc_run(alerts=groups, new=[g["signature"] for g in groups], denied_total=900, ingest={"firewalls": firewalls}), PREVIOUS)
    assert kinds(items) == ["new-high-alert"] * 3 and [item["id"] for item in items] == ["1-new-high-alert", "2-new-high-alert", "3-new-high-alert"]
    mixed = socbot.escalations(esc_run(alerts=groups[:1], new=[groups[0]["signature"]], denied_total=900, ingest={"firewalls": firewalls}), PREVIOUS)
    assert kinds(mixed) == ["new-high-alert", "deny-spike", "firewall-quiet"]
    assert socbot.escalations(esc_run(), PREVIOUS) == []  # nothing triggers: an empty queue


def test_report_gains_one_line_only_when_it_escalates():
    assert "escalated" not in socbot.build_report(quiet_run())
    items = [{"id": "1-deny-spike", "kind": "deny-spike"}, {"id": "2-firewall-quiet", "kind": "firewall-quiet"}]
    text = socbot.build_report(quiet_run(escalated=items))
    assert "➡️ escalated to socagent: 2 item(s): deny-spike, firewall-quiet" in text
    assert socbot.build_report(quiet_run(escalated=[])) == socbot.build_report(quiet_run())


def test_queue_file_shape_mode_and_atomic_replace(tmp_path):
    import os, stat
    path = tmp_path / "state" / "socbot-escalations.json"
    socbot.write_escalations(path, [], NOW)
    assert json.loads(path.read_text()) == {"at": NOW, "items": []} and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    item = {"id": "1-deny-spike", "kind": "deny-spike", "summary": "s", "facts": {"denied_total": 5}}
    socbot.write_escalations(path, [item], NOW + 1)
    assert json.loads(path.read_text()) == {"at": NOW + 1, "items": [item]} and [p.name for p in path.parent.iterdir()] == [path.name]


def test_main_baseline_run_escalates_nothing_then_next_run_compares_with_the_snapshot(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(socbot, "STATE", tmp_path / "socbot.json")
    monkeypatch.setattr(socbot, "ESCALATIONS", tmp_path / "queue.json")
    spike = {"rows": [], "row_count": 400, "truncated": False}
    replies = {"alert_counts": {"rows": [alert("brand-new", "critical")], "row_count": 1, "truncated": False},
               "query_flows": spike, "ingest_status": {"firewalls": []}, "fabric_status": {"subjects": []}}
    monkeypatch.setattr(socbot, "mcp_call_tools", lambda server, calls: [replies[calls[0][0]]])
    queue = lambda: json.loads((tmp_path / "queue.json").read_text())["items"]
    socbot.main()
    assert queue() == [] and "escalated" not in capsys.readouterr().out and json.loads((tmp_path / "socbot.json").read_text())["last"]["denied_total"] == 1200
    replies["alert_counts"] = {"rows": [alert("another-new", "high")], "row_count": 1, "truncated": False}
    socbot.main()
    assert kinds(queue()) == ["new-high-alert"]  # the deny total did not triple, the second night's new signature did
    assert "➡️ escalated to socagent: 1 item(s): new-high-alert" in capsys.readouterr().out


def test_failed_query_leaves_the_queue_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(socbot, "STATE", tmp_path / "socbot.json")
    monkeypatch.setattr(socbot, "ESCALATIONS", tmp_path / "queue.json")
    monkeypatch.setattr(socbot, "mcp_call_tools", lambda server, calls: (_ for _ in ()).throw(RuntimeError("down")))
    socbot.main()
    assert not (tmp_path / "queue.json").exists()
