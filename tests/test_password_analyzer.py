import sys
from pathlib import Path


# Allow Python to find the backend folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent

BACKEND_FOLDER = PROJECT_ROOT / "backend"

sys.path.insert(
    0,
    str(BACKEND_FOLDER)
)


from password_analyzer import (
    analyze_password,
    detect_sequences,
    detect_keyboard_pattern,
    detect_repeated_substring,
    detect_predictable_structure,
    estimate_entropy,
    check_password_policy
)


# ============================================================
# TEST 1 — EMPTY PASSWORD
# ============================================================

def test_empty_password():

    result = analyze_password("")

    assert result["score"] == 0

    assert result["classification"] == "VERY WEAK"


# ============================================================
# TEST 2 — SHORT PASSWORD
# ============================================================

def test_short_password():

    result = analyze_password("1234")

    assert result["classification"] in [
        "VERY WEAK",
        "WEAK"
    ]


# ============================================================
# TEST 3 — SEQUENCE DETECTION
# ============================================================

def test_sequence_detection():

    assert detect_sequences("abc1234") is True

    assert detect_sequences("HelloWorld") is False


# ============================================================
# TEST 4 — KEYBOARD PATTERN
# ============================================================

def test_keyboard_pattern():

    assert detect_keyboard_pattern(
        "qwerty123"
    ) is True

    assert detect_keyboard_pattern(
        "A7!kP2@xQ9#Lm4"
    ) is False


# ============================================================
# TEST 5 — REPEATED SUBSTRING
# ============================================================

def test_repeated_substring():

    assert detect_repeated_substring(
        "abcabc"
    ) is True

    assert detect_repeated_substring(
        "A7!kP2@xQ9#Lm4"
    ) is False


# ============================================================
# TEST 6 — PREDICTABLE STRUCTURE
# ============================================================

def test_predictable_structure():

    assert detect_predictable_structure(
        "password123"
    ) is True

    assert detect_predictable_structure(
        "A7!kP2@xQ9#Lm4"
    ) is False


# ============================================================
# TEST 7 — ENTROPY
# ============================================================

def test_entropy():

    weak_entropy = estimate_entropy(
        "1234"
    )

    strong_entropy = estimate_entropy(
        "A7!kP2@xQ9#Lm4"
    )

    assert strong_entropy > weak_entropy


# ============================================================
# TEST 8 — PASSWORD POLICY
# ============================================================

def test_password_policy():

    policy = check_password_policy(
        "A7!kP2@xQ9#Lm4"
    )

    assert policy["minimum_length"] is True

    assert policy["maximum_length"] is True

    assert policy["has_lowercase"] is True

    assert policy["has_uppercase"] is True

    assert policy["has_digit"] is True

    assert policy["has_symbol"] is True

    assert policy["passed"] is True


# ============================================================
# TEST 9 — STRONG PASSWORD SCORE
# ============================================================

def test_strong_password():

    result = analyze_password(
        "A7!kP2@xQ9#Lm4"
    )

    assert result["score"] >= 80

    assert result["classification"] == "VERY STRONG"


# ============================================================
# TEST 10 — PASSWORD METRICS
# ============================================================

def test_password_metrics():

    result = analyze_password(
        "A7!kP2@xQ9#Lm4"
    )

    metrics = result["metrics"]

    assert metrics["length"] == 14

    assert metrics["lowercase"] is True

    assert metrics["uppercase"] is True

    assert metrics["digits"] is True

    assert metrics["symbols"] is True

    assert metrics["unique_characters"] > 10