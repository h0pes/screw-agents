"""Download CWE-1400 view XML from MITRE and emit a YAML hierarchy file.

Run once per CWE release (MITRE updates quarterly). Outputs are committed:
  - benchmarks/data/cwe-1400-source.xml (audit trail)
  - benchmarks/data/cwe-1400-hierarchy.yaml (runtime artifact)

See ADR-013 for why we use CWE-1400 (not CWE-1000).
"""
from __future__ import annotations

import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

import yaml


CWE_VIEW_URL = "https://cwe.mitre.org/data/xml/views/1400.xml.zip"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = REPO_ROOT / "benchmarks" / "data"
SOURCE_XML = DATA_DIR / "cwe-1400-source.xml"
HIERARCHY_YAML = DATA_DIR / "cwe-1400-hierarchy.yaml"

# CWE XML uses this default namespace
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


def download_cwe_xml() -> bytes:
    """Fetch the CWE-1400 zipped XML from MITRE and return the inner XML bytes."""
    print(f"Downloading {CWE_VIEW_URL} ...")
    with urllib.request.urlopen(CWE_VIEW_URL) as response:
        zip_bytes = response.read()
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(xml_name)


def parse_cwe_xml(xml_bytes: bytes) -> dict[str, Any]:
    """Parse the CWE XML into a hierarchy dict suitable for YAML serialization."""
    root = ET.fromstring(xml_bytes)

    nodes: dict[str, dict[str, Any]] = {}
    view_members: list[str] = []

    # Parse Weaknesses (base, variant, class entries)
    for weakness in root.iter("{http://cwe.mitre.org/cwe-7}Weakness"):
        cwe_id = f"CWE-{weakness.get('ID')}"
        nodes[cwe_id] = {
            "cwe_id": cwe_id,
            "name": weakness.get("Name", ""),
            "abstraction": weakness.get("Abstraction", ""),
            "parents": [],
            "children": [],
        }
        for rel in weakness.iter("{http://cwe.mitre.org/cwe-7}Related_Weakness"):
            nature = rel.get("Nature", "")
            target_id = f"CWE-{rel.get('CWE_ID')}"
            if nature == "ChildOf":
                nodes[cwe_id]["parents"].append(target_id)
            elif nature == "ParentOf":
                nodes[cwe_id]["children"].append(target_id)

    # Parse Categories (the CWE-14xx grouping entries)
    for cat in root.iter("{http://cwe.mitre.org/cwe-7}Category"):
        cwe_id = f"CWE-{cat.get('ID')}"
        nodes[cwe_id] = {
            "cwe_id": cwe_id,
            "name": cat.get("Name", ""),
            "abstraction": "Category",
            "parents": [],
            "children": [],
        }
        for member in cat.iter("{http://cwe.mitre.org/cwe-7}Has_Member"):
            member_id = f"CWE-{member.get('CWE_ID')}"
            nodes[cwe_id]["children"].append(member_id)
            if member_id in nodes:
                nodes[member_id]["parents"].append(cwe_id)

    # Parse the top-level View for CWE-1400 itself
    for view in root.iter("{http://cwe.mitre.org/cwe-7}View"):
        if view.get("ID") == "1400":
            for member in view.iter("{http://cwe.mitre.org/cwe-7}Has_Member"):
                view_members.append(f"CWE-{member.get('CWE_ID')}")

    # Deduplicate parent/child lists (MITRE XML repeats across views)
    for node in nodes.values():
        node["parents"] = list(dict.fromkeys(node["parents"]))
        node["children"] = list(dict.fromkeys(node["children"]))

    return {
        "view_id": "CWE-1400",
        "view_name": "Comprehensive Categorization",
        "source_url": CWE_VIEW_URL,
        "extracted_at": _now_iso(),
        "node_count": len(nodes),
        "view_members": sorted(view_members),
        "nodes": nodes,
    }


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    xml_bytes = download_cwe_xml()
    SOURCE_XML.write_bytes(xml_bytes)
    print(f"Wrote {SOURCE_XML} ({len(xml_bytes):,} bytes)")

    hierarchy = parse_cwe_xml(xml_bytes)
    with HIERARCHY_YAML.open("w") as f:
        yaml.safe_dump(hierarchy, f, sort_keys=False, width=100)
    print(f"Wrote {HIERARCHY_YAML} ({hierarchy['node_count']} nodes, "
          f"{len(hierarchy['view_members'])} view members)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
