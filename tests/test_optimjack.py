"""The 16 Nov 2026 Optimizely ("OptimJack") attack: every loader variant is blocked at the gate,
ordinary experiment changes pass without humans."""

import pytest

import optimjack_fixtures as F
from authority import script_integrity as S

BASE = F.snippet()


@pytest.mark.parametrize("name", ["LOADER_1", "LOADER_2", "LOADER_3", "LOADER_3_ONLY_INLINE", "PAYLOAD_AS_UPDATE"])
def test_every_attack_variant_is_blocked(name):
    r = S.check(BASE, getattr(F, name))
    assert r["verdict"] == "block", r["findings"]


@pytest.mark.parametrize("name", ["BENIGN_NEW_EXPERIMENT", "BENIGN_VARIATION_CODE"])
def test_ordinary_experiment_changes_pass(name):
    assert S.check(BASE, getattr(F, name))["verdict"] == "pass"


def test_hidden_payload_is_decoded_and_seen():
    caps = S.capabilities(F.LOADER_3_ONLY_INLINE)
    assert caps["hidden_code"]
    assert {"native_hooks", "card_logic", "screenshot", "ios_targeting", "hidden_iframe"} <= caps["caps"]
    assert "collector-1688.invalid" in caps["hosts"]


def test_loader_to_vendors_own_allowlisted_host_goes_to_review_not_block():
    own = F.snippet(extra="(function(){var s=document.createElement('script');"
                          "s.src='https://cdn.optimizely-like.example.com/js/module2.js';document.head.appendChild(s);})();")
    r = S.check(BASE, own, allowed_hosts=["cdn.optimizely-like.example.com"])
    assert r["verdict"] == "review"
