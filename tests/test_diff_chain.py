"""Offline unit tests for the diff chain + seed-layer extractor."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.diff_chain import diff
from pipeline.anchor_identify import carried_from_seed


def _seed():
    return {
        "build": 100,
        "anchor": {"shape": "C", "holder_global": "0x7B72F0",
                   "field_disp": "0x58",
                   "store_ctx": {"pattern": "E8 ?? ?? ?? ?? 48 89 47 58",
                                 "field_disp": "0x58"},
                   "consumer_pattern": "48 8B 05 ?? ?? ?? ?? 48 8B 90"},
        "structs": {"top": {"offset": 16}, "ci": {"offset": 32}},
        "functions": [{"name": "foo", "pattern": "90 90"}],
    }


def test_diff_no_drift():
    rep = diff(_seed(), _seed(), {"foo": "unique"})
    assert rep["anchor"]["changed"] is False
    assert not [k for k, v in rep["structs"].items() if v["changed"]]
    ps = rep["functions"]["pattern_survival"]
    assert ps["survival_rate"] == 1.0 and ps["unique"] == 1


def test_diff_anchor_and_struct_drift():
    fresh = _seed()
    fresh["build"] = 101
    fresh["anchor"]["holder_global"] = "0x800000"
    fresh["structs"]["ci"] = {"offset": 40}
    rep = diff(_seed(), fresh, {"foo": "dead"})
    assert rep["anchor"]["changed"]
    assert rep["anchor"]["holder_global"]["fresh"] == "0x800000"
    assert rep["structs"]["ci"]["changed"]
    assert rep["functions"]["pattern_survival"]["dead"] == 1
    assert rep["functions"]["pattern_survival"]["survival_rate"] == 0.0


def test_diff_reg_delta():
    a, b = _seed(), _seed()
    a["functions"] = [{"name": "gone", "pattern": "90"}]
    b["functions"] = [{"name": "brand_new", "pattern": "90"}]
    rep = diff(a, b, {})
    gt = rep["functions"]["ground_truth"]
    assert gt["gone_names"] == ["gone"] and gt["new_names"] == ["brand_new"]


def test_carried_from_schema2_seed():
    c = carried_from_seed(_seed())
    assert c["consumer"]["pattern"] == "48 8B 05 ?? ?? ?? ?? 48 8B 90"
    assert c["store_ctx"]["pattern"].startswith("E8 ?? ?? ?? ?? ")


def test_carried_from_v1_seed_rebuilds_window():
    v1 = {"chosen": {
        "record": {"pattern": "48 8B 05 ?? ?? ?? ?? 48 8B 90 40 03 00 00",
                   "pattern_len": 14},
        "shape_c": {"records": [{"store_pattern": "48 89 47 58",
                                 "field_disp": "0x58"}]}}}
    c = carried_from_seed(v1)
    assert c["store_ctx"]["pattern"] == "E8 ?? ?? ?? ?? 48 89 47 58"
    assert c["store_ctx"]["field_disp"] == "0x58"
    assert c["consumer"]["pattern_len"] == 14
