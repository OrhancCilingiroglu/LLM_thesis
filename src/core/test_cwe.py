"""Tests for CWE hierarchy parsing and relationship classification.

The classification tests use real chains hand-verified against MITRE's raw
catalogue XML before trusting this module (see cwe.py's module docstring):
CWE-89 (SQL injection) ChildOf CWE-943 ChildOf CWE-74 ChildOf CWE-707, and
CWE-79 (XSS) ChildOf CWE-74 directly -- a sibling of CWE-943, not of CWE-89.
"""

from pathlib import Path

import pytest

from cwe import CweCatalog, CweHierarchy, load_catalog, parse_catalog_xml

HERE = Path(__file__).parent
CACHED_HIERARCHY = HERE / "data" / "cwe_hierarchy.json"

requires_cached_hierarchy = pytest.mark.skipif(
    not CACHED_HIERARCHY.exists(), reason="cached cwe_hierarchy.json not built"
)


# --------------------------------------------------------------------------- #
# Synthetic catalog: fast, no dependency on the real cached data
# --------------------------------------------------------------------------- #
#
#          707
#           |
#           74
#          /  \
#        943   79
#         |
#         89

SYNTHETIC = CweCatalog(
    version="test",
    date="2000-01-01",
    view_id="1000",
    names={707: "Pillar", 74: "Injection", 943: "Data Query Logic", 79: "XSS", 89: "SQLi", 999: "Unrelated Root"},
    parents={74: frozenset({707}), 943: frozenset({74}), 79: frozenset({74}), 89: frozenset({943})},
)


@pytest.fixture
def hierarchy() -> CweHierarchy:
    return CweHierarchy(SYNTHETIC)


def test_exact_match(hierarchy):
    assert hierarchy.classify(89, 89) == "exact"


def test_reported_ancestor_of_target(hierarchy):
    """The Section 1.3 pattern: tool reports a generic ancestor of the true CWE."""
    assert hierarchy.classify(943, 89) == "ancestor"
    assert hierarchy.classify(74, 89) == "ancestor"
    assert hierarchy.classify(707, 89) == "ancestor"


def test_reported_descendant_of_target(hierarchy):
    """Inverse of the ancestor case: report is narrower than the target."""
    assert hierarchy.classify(89, 943) == "descendant"
    assert hierarchy.classify(89, 74) == "descendant"


def test_direct_siblings(hierarchy):
    """79 and 943 share a direct parent (74); 89 does not share one with 79."""
    assert hierarchy.classify(79, 943) == "sibling"
    assert hierarchy.classify(943, 79) == "sibling"


def test_shared_distant_ancestor_is_not_sibling(hierarchy):
    """79 and 89 both trace back to 707, but do not share a *direct* parent."""
    assert hierarchy.classify(79, 89) == "unrelated"
    assert hierarchy.classify(89, 79) == "unrelated"


def test_unrelated_branches(hierarchy):
    assert hierarchy.classify(999, 89) == "unrelated"


def test_unknown_id_is_none(hierarchy):
    assert hierarchy.classify(123456, 89) == "none"
    assert hierarchy.classify(89, 123456) == "none"


def test_ancestors_are_transitive_and_deduplicated(hierarchy):
    assert hierarchy.ancestors(89) == frozenset({943, 74, 707})


def test_root_node_has_no_ancestors(hierarchy):
    assert hierarchy.ancestors(707) == frozenset()


# --------------------------------------------------------------------------- #
# Real catalogue: parsing correctness and the hand-verified chains
# --------------------------------------------------------------------------- #


@requires_cached_hierarchy
def test_cached_hierarchy_matches_known_sql_injection_chain():
    catalog = load_catalog(CACHED_HIERARCHY)
    hierarchy = CweHierarchy(catalog)
    assert hierarchy.classify(943, 89) == "ancestor"
    assert hierarchy.classify(74, 89) == "ancestor"
    assert hierarchy.classify(707, 89) == "ancestor"


@requires_cached_hierarchy
def test_cached_hierarchy_matches_known_xss_sibling_relationship():
    catalog = load_catalog(CACHED_HIERARCHY)
    hierarchy = CweHierarchy(catalog)
    # CWE-79 (XSS) and CWE-943 are both direct children of CWE-74.
    assert hierarchy.classify(79, 943) == "sibling"
    # CWE-79 and CWE-89 only share the more distant CWE-74/707 ancestors.
    assert hierarchy.classify(79, 89) == "unrelated"


@requires_cached_hierarchy
def test_cached_hierarchy_has_plausible_scale():
    catalog = load_catalog(CACHED_HIERARCHY)
    assert catalog.version  # non-empty
    assert len(catalog.all_ids) > 900  # CWE 4.x has roughly ~950-1000 Weakness entries
    assert 89 in catalog.all_ids and 79 in catalog.all_ids


def test_parse_catalog_xml_ignores_non_hierarchy_relationships(tmp_path):
    """PeerOf/CanPrecede/etc. must not leak into the hierarchy edges."""
    xml = tmp_path / "fake.xml"
    xml.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="test" Date="2000-01-01"
                   xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="1" Name="Root"/>
    <Weakness ID="2" Name="Child">
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="1" View_ID="1000"/>
        <Related_Weakness Nature="PeerOf" CWE_ID="1" View_ID="1000"/>
        <Related_Weakness Nature="ChildOf" CWE_ID="1" View_ID="1003"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>""", encoding="utf-8")
    catalog = parse_catalog_xml(xml, view_id="1000")
    assert catalog.parents[2] == frozenset({1})  # only the View-1000 ChildOf edge
    assert catalog.all_ids == frozenset({1, 2})


def test_save_and_load_round_trip(tmp_path):
    from cwe import save_catalog
    out = tmp_path / "hierarchy.json"
    save_catalog(SYNTHETIC, out)
    restored = load_catalog(out)
    assert restored == SYNTHETIC
