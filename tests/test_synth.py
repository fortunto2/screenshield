from itertools import islice

from screenshield.synth import gen_frame_events, planted_incidents


def test_volume_math_small():
    rows = list(gen_frame_events(rooms=2, days=1, keyframe_every_s=60, hours_per_day=1))
    assert len(rows) == 2 * 60


def test_planted_stories():
    fe, fi, tc = planted_incidents()
    kinds = {f["kind"] for f in fi}
    assert kinds == {"leak", "quishing", "injection"}
    assert sum(1 for f in fi if f["kind"] == "quishing") == 31
    assert tc[0]["verdict"] == "blocked" and tc[0]["tainted"] == 1


def test_generator_is_lazy():
    assert len(list(islice(gen_frame_events(rooms=10_000), 5))) == 5
