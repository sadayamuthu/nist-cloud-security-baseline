import re
from src.ncsb.generate import normalize_id

def test_normalize_base():
    assert normalize_id("ac-2") == "AC-2"

def test_normalize_enhancement():
    assert normalize_id("AC-2 (01)") == "AC-2(1)"
