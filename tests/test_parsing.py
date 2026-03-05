from bgp_route_analyzer import _parse_bgp_table

SAMPLE_BGP_OUTPUT = """\
BGP table version is 5, local router ID is 10.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.0.0.0/8       192.168.1.1              0    100      0 65001 i
*> 172.16.0.0/12    192.168.1.2            100    200     10 65002 65003 i
*> 192.168.0.0/16   0.0.0.0                  0    100      0 i
"""


def test_parse_returns_correct_count():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    assert len(result) == 3


def test_parse_extracts_network():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    networks = [r["network"] for r in result]
    assert "10.0.0.0/8" in networks
    assert "172.16.0.0/12" in networks
    assert "192.168.0.0/16" in networks


def test_parse_extracts_next_hop():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    first = next(r for r in result if r["network"] == "10.0.0.0/8")
    assert first["next_hop"] == "192.168.1.1"


def test_parse_extracts_as_path():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    multi_hop = next(r for r in result if r["network"] == "172.16.0.0/12")
    assert "65002" in multi_hop["as_path"]
    assert "65003" in multi_hop["as_path"]


def test_parse_extracts_origin():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    first = next(r for r in result if r["network"] == "10.0.0.0/8")
    assert first["origin"] == "i"


def test_parse_extracts_metrics():
    result = _parse_bgp_table(SAMPLE_BGP_OUTPUT)
    multi_hop = next(r for r in result if r["network"] == "172.16.0.0/12")
    assert multi_hop["metric"] == "100"
    assert multi_hop["local_pref"] == "200"
    assert multi_hop["weight"] == "10"


def test_parse_empty_input():
    assert _parse_bgp_table("") == []


def test_parse_no_routes():
    result = _parse_bgp_table("BGP table version is 1\n\n")
    assert result == []
