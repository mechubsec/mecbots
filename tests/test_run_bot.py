"""Checks for run_bot's Discord-safe model text. Run: python3 -m pytest tests"""

import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("run_bot", Path(__file__).resolve().parent.parent / "bin" / "run_bot.py")
run_bot = importlib.util.module_from_spec(spec)
sys.modules["run_bot"] = run_bot
spec.loader.exec_module(run_bot)


def test_defang_mentions_links_and_controls():
    text = run_bot.defang('ping @everyone <@123> [docs](https://evil.example/x) [t](https://e.example "Trusted")\x07\n- ok')
    assert "@everyone" not in text and "<@123>" not in text and "](" not in text
    assert "\x07" not in text and "\n- ok" in text


# --- two-tier reporting ---

import stat




def test_scrub_addresses_and_macs():
    text = run_bot.scrub("gw 192.0.2.1:8006, 198.51.100.0/24, 2001:db8::1 and 2001:db8::5, mac AA:BB:CC:dd:ee:ff, at 07:30:00", [])
    assert text == "gw [ip]:8006, [ip]/24, [ip] and [ip], mac [mac], at 07:30:00"


def test_scrub_keeps_versions_but_redacts_when_unsure():
    kept = ["version 1.99.2.0", "v1.99.2.0", "upstream 1.99.2.0", "Version: 1.99.2.0", "1.2.3.4.5", "5.1.2.3.4", "300.1.1.1"]
    assert [run_bot.scrub(text, []) for text in kept] == kept
    assert run_bot.scrub("vrdcbot: 1.98.0.1 → 1.99.2.0 upstream", []) == "vrdcbot: [ip] → 1.99.2.0 upstream"  # unsure about the left one: redacted
    assert run_bot.scrub("latest → 1.99.2.0 upgrade", []) == "latest → 1.99.2.0 upgrade"
    assert run_bot.scrub("dev 203.0.113.1 and host203.0.113.2.", []) == "dev [ip] and host[ip]."
    assert run_bot.scrub("src 198.51.100.1 → 198.51.100.2 denied", []) == "src [ip] → [ip] denied"


def test_scrub_names_case_longest_first_subdomain_whole_token():
    names = ["labhost", "labhost-prod", "example.org", "*.corp.example", "HOST2"]
    text = run_bot.scrub("LABHOST-Prod up, labhost down, labhost2 fine, a.b.example.org, example.org., x.corp.example, host2.", names)
    assert text == "[name] up, [name] down, labhost2 fine, [name], [name]., [name], [name]."
    assert run_bot.scrub("sublabhost and notexample.org", names) == "sublabhost and notexample.org"
    assert run_bot.scrub("🔴 diskbot: 3 checks ✅", names) == "🔴 diskbot: 3 checks ✅"


def test_load_names_comments_and_missing(tmp_path):
    path = tmp_path / "redact.txt"
    path.write_text("# lab\nfoo\n\n  bar  \n")
    assert run_bot.load_names(path) == ["foo", "bar"]
    assert run_bot.load_names(tmp_path / "nope.txt") is None


def test_save_report_modes_prune_and_index_escaping(tmp_path):
    root = tmp_path / "reports"
    for index in range(run_bot.KEEP_REPORTS + 3):
        run_bot.save_report(run_bot.Path("socbot") / f"2026-01-01_{index:04d}.md", f"full {index} 192.0.2.1", root)
    run_bot.save_report(run_bot.Path("<b>&bot") / "2026-01-02_0000.md", "x", root)
    files = sorted((root / "socbot").glob("*.md"))
    assert len(files) == run_bot.KEEP_REPORTS and files[0].name == "2026-01-01_0003.md"
    assert "192.0.2.1" in files[-1].read_text()  # local copy is unredacted
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in (root, root / "socbot"))
    page = (root / "index.html").read_text()
    assert "<b>&bot" not in page and "&lt;b&gt;&amp;bot" in page and "<script" not in page
    assert page.index("2026-01-01_0062.md") < page.index("2026-01-01_0061.md")  # newest first


def _fake_bot(tmp_path, monkeypatch, argv):
    (tmp_path / "bots" / "fake").mkdir(parents=True, exist_ok=True)
    (tmp_path / "bots" / "fake" / "report.py").write_text('print("REPORT START\\nhost hostx at 192.0.2.3 ✅\\nREPORT END")')
    (tmp_path / "redact.txt").write_text("hostx\n")
    monkeypatch.setattr(run_bot, "REPO", tmp_path)
    monkeypatch.setattr(run_bot, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(run_bot, "REDACT_FILE", tmp_path / "redact.txt")
    monkeypatch.setattr(sys, "argv", ["run_bot.py", "fake", *argv])


def test_dry_run_scrubs_and_writes_nothing(tmp_path, monkeypatch, capsys):
    _fake_bot(tmp_path, monkeypatch, ["--dry-run"])
    assert run_bot.main() == 0
    out = capsys.readouterr().out
    assert "host [name] at [ip] ✅" in out and "full report kept local: fake/" in out and "would be saved" in out
    assert not (tmp_path / "reports").exists()
    _fake_bot(tmp_path, monkeypatch, ["--dry-run", "--full"])
    assert run_bot.main() == 0 and "host hostx at 192.0.2.3" in capsys.readouterr().out


def test_post_sends_scrubbed_text_and_missing_list_is_noted(tmp_path, monkeypatch):
    _fake_bot(tmp_path, monkeypatch, [])
    (tmp_path / "redact.txt").unlink()
    sent = {}
    monkeypatch.setattr(run_bot.subprocess, "run", lambda cmd, **kw: sent.update(cmd=cmd, text=kw.get("input")) or type("R", (), {"returncode": 0, "stdout": "REPORT START\nhost hostx at 192.0.2.3\nREPORT END", "stderr": ""})())
    assert run_bot.main() == 0
    assert "[ip]" in sent["text"] and "192.0.2.3" not in sent["text"] and "redact list missing" in sent["text"]
    assert (tmp_path / "reports" / "fake").glob("*.md")
    assert "192.0.2.3" in next((tmp_path / "reports" / "fake").glob("*.md")).read_text()


def test_scrub_failure_stops_post_and_save_failure_does_not(tmp_path, monkeypatch):
    _fake_bot(tmp_path, monkeypatch, [])
    posted = []
    real_run = run_bot.subprocess.run
    monkeypatch.setattr(run_bot.subprocess, "run", lambda cmd, **kw: posted.append(cmd) or real_run(["true"]) if cmd[0] == "hermes" else real_run(cmd, **kw))
    monkeypatch.setattr(run_bot, "save_report", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    assert run_bot.main() == 0 and posted  # post still happens
    posted.clear()
    monkeypatch.setattr(run_bot, "scrub", lambda *args: (_ for _ in ()).throw(RuntimeError("boom")))
    assert run_bot.main() == 1 and not posted
