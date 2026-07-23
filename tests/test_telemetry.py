from app.services.telemetry import normalize_evidence, parse_df, parse_free, parse_uptime, parse_vmstat


def test_parse_free() -> None:
    parsed = parse_free("""              total        used        free      shared  buff/cache   available
Mem:           15Gi       5.0Gi       2.0Gi       100Mi       8.0Gi       9.0Gi
Swap:         2.0Gi       100Mi       1.9Gi
""")
    assert parsed["memory"]["available"] == "9.0Gi"
    assert parsed["swap"]["used"] == "100Mi"


def test_parse_df() -> None:
    parsed = parse_df("""Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/sda2      xfs    100G   91G   9G  91% /
""")
    assert parsed["filesystems"][0]["used_percent"] == 91
    assert parsed["filesystems"][0]["mount"] == "/"


def test_parse_uptime() -> None:
    parsed = parse_uptime(" 16:10:01 up 10 days, load average: 0.25, 0.20, 0.10")
    assert parsed["load_1m"] == 0.25


def test_parse_vmstat() -> None:
    parsed = parse_vmstat("""procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
r b swpd free buff cache si so bi bo in cs us sy id wa st
1 0 0 100 10 500 0 0 1 2 100 200 1 1 97 1 0
0 0 0 100 10 500 0 0 2 3 100 200 2 1 95 2 0
""")
    assert parsed["averages"]["wa"] == 2.0


def test_normalize_unknown() -> None:
    assert normalize_evidence("echo ok", "ok") == {}
