from pathlib import Path
import yara
from typing import Optional


class YaraScanner:
    """Handles loading and matching of YARA rules."""

    def __init__(self):
        self.rules: Optional[yara.Rules] = self._load_rules()

    def _load_rules(self) -> Optional[yara.Rules]:
        rules_dir = Path(__file__).parent.parent / "yara_rules"
        if not rules_dir.exists():
            print("Warning: yara_rules folder not found")
            return None

        rule_files = {f.stem: str(f) for f in rules_dir.glob("*.yar")}
        if not rule_files:
            print("Warning: No YARA rules found")
            return None

        try:
            rules = yara.compile(filepaths=rule_files)
            print(f"Loaded {len(rule_files)} YARA rules")
            return rules
        except yara.SyntaxError as e:
            print(f"YARA syntax error: {e}")
            return None

    def match(self, file_path: Path) -> list:
        """Return list of matched YARA rule names."""
        if not self.rules:
            return []

        try:
            matches = self.rules.match(str(file_path))
            return [m.rule for m in matches]
        except Exception as e:
            print(f"YARA error on {file_path}: {e}")
            return []