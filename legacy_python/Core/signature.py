from typing import Dict, Optional


class SignatureDatabase:
    """In-memory signature database supporting multiple hash algorithms."""

    def __init__(self):
        self.signatures: Dict[str, Dict[str, str]] = {}  # malware_name → {algo: hash}
        self._load_known_signatures()

    def _load_known_signatures(self):
        """
        In real-world: load from file, database, or API.
        For now: small hardcoded set for testing.
        """
        # EICAR test file (add multiple hashes)
        self.signatures["EICAR-Test-File"] = {
            "md5": "44d88612fea8a8f36de82e1278abb02f",
            "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
            "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        }

        # You can add more malware entries like this:
        # self.signatures["Example-Malware"] = {
        #     "md5": "...",
        #     "sha256": "...",
        # }

    def check_hashes(self, computed_hashes: Dict[str, str]) -> Optional[str]:
        """Check if computed hashes match any known malware (any algorithm match)."""
        for malware_name, stored_hashes in self.signatures.items():
            for algo, stored_hash in stored_hashes.items():
                if algo in computed_hashes and computed_hashes[algo] == stored_hash:
                    return malware_name
        return None

    def add_signature(self, malware_name: str, algo: str, hash_value: str):
        """Add a new hash for a malware."""
        if malware_name not in self.signatures:
            self.signatures[malware_name] = {}
        self.signatures[malware_name][algo] = hash_value