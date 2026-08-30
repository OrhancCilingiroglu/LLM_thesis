"""CWE taxonomy: parsing MITRE's catalogue, hierarchy, and relationship matching.

Detection scoring elsewhere in this project (project/core/cwe_correlations.py,
analyser.py, cwe_summary.py) requires an exact CWE match between a tool's
finding and a sample's target CWE. methodology-plan.md Section 1.3 notes tools
routinely report a generic ancestor instead (CWE-668, 693, 497 show up this
way in the cross-CWE matrix) and asks for a hierarchy-aware classification
alongside the strict one, not a replacement for it.

This module builds that hierarchy from MITRE's CWE catalogue XML
(cwec_latest.xml.zip from https://cwe.mitre.org/data/xml/), using only the
`ChildOf` relationships scoped to View 1000 ("Research Concepts") -- the view
methodology-plan.md specifies, and the one that gives a clean is-a hierarchy
rather than the looser associations (PeerOf, CanPrecede, CanAlsoBe, Requires,
StartsWith) the catalogue also carries. Verified against known chains before
trusting it, e.g. CWE-89 (SQL injection) ChildOf CWE-943 ChildOf CWE-74
ChildOf CWE-707 (Pillar), and CWE-79 (XSS) also ChildOf CWE-74 -- a sibling of
CWE-943, not of CWE-89 directly.

Parsing the ~18 MB source XML is one-off; the derived hierarchy (id -> direct
parents, a few hundred KB) is cached as JSON in data/ and is what callers
normally load. Nothing in this module is pipeline/tool output -- it is
vendored reference data, on the same footing as a config file, and is
re-derived by re-running build_from_xml(), not by re-scanning any sample.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

CWE_XML_NS = {"c": "http://cwe.mitre.org/cwe-7"}
DEFAULT_VIEW_ID = "1000"  # "Research Concepts" -- the hierarchical decomposition
DEFAULT_HIERARCHY_PATH = Path(__file__).parent / "data" / "cwe_hierarchy.json"

RelationshipKind = str  # "exact" | "ancestor" | "descendant" | "sibling" | "unrelated" | "none"


@dataclass(frozen=True)
class CweCatalog:
    """The subset of MITRE's catalogue needed for hierarchy matching."""

    version: str
    date: str
    view_id: str
    names: dict[int, str]
    parents: dict[int, frozenset[int]]  # cwe_id -> direct ChildOf parents in `view_id`

    @property
    def all_ids(self) -> frozenset[int]:
        return frozenset(self.names)


def parse_catalog_xml(xml_path: str | Path, view_id: str = DEFAULT_VIEW_ID) -> CweCatalog:
    """Parse MITRE's cwec_*.xml into a CweCatalog scoped to one hierarchy view.

    Only `Nature="ChildOf"` edges tagged with `view_id` are kept. The catalogue
    also carries PeerOf/CanPrecede/CanAlsoBe/Requires/StartsWith relationships,
    which are real associations but not is-a hierarchy and would corrupt
    ancestor/descendant classification if included.
    """
    root = ET.parse(xml_path).getroot()
    weaknesses_el = root.find("c:Weaknesses", CWE_XML_NS)
    if weaknesses_el is None:
        raise ValueError(f"{xml_path}: no <Weaknesses> element -- not a CWE catalogue export")

    names: dict[int, str] = {}
    parents: dict[int, set[int]] = {}
    for weakness in weaknesses_el.findall("c:Weakness", CWE_XML_NS):
        cwe_id = int(weakness.get("ID"))
        names[cwe_id] = weakness.get("Name", "")

        related = weakness.find("c:Related_Weaknesses", CWE_XML_NS)
        if related is None:
            continue
        for rel in related.findall("c:Related_Weakness", CWE_XML_NS):
            if rel.get("Nature") == "ChildOf" and rel.get("View_ID") == view_id:
                parents.setdefault(cwe_id, set()).add(int(rel.get("CWE_ID")))

    return CweCatalog(
        version=root.get("Version", ""),
        date=root.get("Date", ""),
        view_id=view_id,
        names=names,
        parents={cwe_id: frozenset(p) for cwe_id, p in parents.items()},
    )


def save_catalog(catalog: CweCatalog, path: str | Path = DEFAULT_HIERARCHY_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": catalog.version,
        "date": catalog.date,
        "view_id": catalog.view_id,
        "names": {str(k): v for k, v in catalog.names.items()},
        "parents": {str(k): sorted(v) for k, v in catalog.parents.items()},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")


def load_catalog(path: str | Path = DEFAULT_HIERARCHY_PATH) -> CweCatalog:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return CweCatalog(
        version=data["version"],
        date=data["date"],
        view_id=data["view_id"],
        names={int(k): v for k, v in data["names"].items()},
        parents={int(k): frozenset(v) for k, v in data["parents"].items()},
    )


def build_from_xml(xml_path: str | Path, out_path: str | Path = DEFAULT_HIERARCHY_PATH,
                    view_id: str = DEFAULT_VIEW_ID) -> CweCatalog:
    """Regenerate the cached hierarchy JSON from a freshly downloaded catalogue.

    Re-run this whenever MITRE ships a new CWE version. Record the resulting
    `catalog.version` wherever hierarchy-aware results are reported, per the
    project's rule that every taxonomy/tool version behind a result is stated.
    """
    catalog = parse_catalog_xml(xml_path, view_id=view_id)
    save_catalog(catalog, out_path)
    return catalog


class CweHierarchy:
    """Ancestor/descendant/sibling classification over a CweCatalog.

    `sibling` means "shares a *direct* parent" -- two CWEs that only share a
    higher, more distant ancestor (e.g. CWE-79 and CWE-89 both eventually
    trace to CWE-707) are classified `unrelated`, since the fixed taxonomy in
    methodology-plan.md Section 1.3 has no "cousin" bucket and stretching
    `sibling` to cover that would blur exactly the distinction the relaxed
    metric is meant to expose.
    """

    def __init__(self, catalog: CweCatalog):
        self.catalog = catalog
        self._ancestor_cache: dict[int, frozenset[int]] = {}

    def ancestors(self, cwe_id: int) -> frozenset[int]:
        """All CWEs reachable by following ChildOf edges upward from `cwe_id`."""
        cached = self._ancestor_cache.get(cwe_id)
        if cached is not None:
            return cached
        seen: set[int] = set()
        stack = list(self.catalog.parents.get(cwe_id, ()))
        while stack:
            parent = stack.pop()
            if parent in seen:
                continue
            seen.add(parent)
            stack.extend(self.catalog.parents.get(parent, ()))
        result = frozenset(seen)
        self._ancestor_cache[cwe_id] = result
        return result

    def classify(self, reported: int, target: int) -> RelationshipKind:
        """Classify a tool/model's `reported` CWE against the `target` CWE.

        `target` is normally the sample's generation-time/ground-truth CWE;
        `reported` is what a tool or judge emitted. Direction matters for
        ancestor vs. descendant: "ancestor" means the report is broader than
        the target (the common "generic ancestor" over-reporting pattern from
        Section 1.3); "descendant" means the report is narrower.
        """
        if reported == target:
            return "exact"

        known = self.catalog.all_ids
        if reported not in known or target not in known:
            return "none"

        if reported in self.ancestors(target):
            return "ancestor"
        if target in self.ancestors(reported):
            return "descendant"

        reported_parents = self.catalog.parents.get(reported, frozenset())
        target_parents = self.catalog.parents.get(target, frozenset())
        if reported_parents & target_parents:
            return "sibling"

        return "unrelated"


def load_hierarchy(path: str | Path = DEFAULT_HIERARCHY_PATH) -> CweHierarchy:
    return CweHierarchy(load_catalog(path))
