"""Put src/ on sys.path, so `python3 -m unittest discover -s tests -t .` works with no env var."""
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
