from screenshield.redact import Region, build_filter, regions_from_findings


def test_filter_graph_has_one_overlay_per_region_with_time_window():
    g, last = build_filter([Region(1.0, 2.5, 10, 20, 100, 30), Region(3.0, 4.0, 0, 0, 50, 50)])
    assert g.count("overlay=") == 2
    assert "between(t,1.000,2.500)" in g
    assert last == "v1"


def test_regions_from_findings_skips_boxless():
    regs = regions_from_findings([{"ts": 1.0, "box": [1, 2, 3, 4]}, {"ts": 2.0, "box": None}])
    assert len(regs) == 1 and regs[0].t_to == 2.0
