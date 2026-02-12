import hashlib
from pathlib import Path
from typing import Dict, Union
import math
from collections import Counter

def get_file_hashes(file_path: Union[str, Path]) -> Dict[str, str]:
    """
    Compute multiple hashes of a file.
    Reads in binary mode for consistency across platforms.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        return {}

    algorithms = ["md5", "sha1", "sha256"]
    hashes = {}

    try:
        with open(file_path, "rb") as f:
            content = f.read()  # Read all bytes at once (for simplicity; chunk if large files)

        for algo in algorithms:
            hash_func = hashlib.new(algo)
            hash_func.update(content)
            hashes[algo] = hash_func.hexdigest()

        return hashes
    except Exception:
        return {}


def is_pe_file(file_path: Union[str, Path]) -> bool:
    """
    Quick check if a file looks like a Windows PE executable.
    Checks for the 'MZ' header at the beginning.
    """
    file_path = Path(file_path)
    try:
        with open(file_path, "rb") as f:
            header = f.read(2)
            return header == b"MZ"
    except:
        return False
    
def calculate_entropy(file_path: Union[str, Path]) -> float:
    """Compute Shannon entropy of file bytes."""
    file_path = Path(file_path)
    if not file_path.is_file():
        return 0.0

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
    except:
        return 0.0