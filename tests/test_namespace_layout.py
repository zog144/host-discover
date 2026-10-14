"""Guard the aggregate-PyPI namespace layout against legacy import paths."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "zog" / "host_discover"

LEGACY_PATTERNS = (
    re.compile(r"(?<!zog\.)\bhost_discover\."),
    re.compile(r"(?<!zog\.)\bhost_identify\."),
    re.compile(r"(?<!zog\.)\bhost_install\."),
    re.compile(r"(?<!zog\.)\bbox_control\."),
)


def test_namespace_layout_has_no_legacy_top_level_package():
    assert PACKAGE.is_dir()
    assert not (ROOT / "src" / "zog" / "__init__.py").exists()
    assert not (ROOT / "host_discover").exists()


def test_installable_source_has_no_legacy_module_paths():
    offenders = []
    for path in PACKAGE.rglob("*.py"):
        text = path.read_text()
        for pattern in LEGACY_PATTERNS:
            if pattern.search(text):
                offenders.append(str(path.relative_to(ROOT)))
                break
    assert offenders == []
