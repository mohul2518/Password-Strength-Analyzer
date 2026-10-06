import re
import math
from pathlib import Path


# ============================================================
# FILE LOCATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

COMMON_PASSWORD_FILE = (
    BASE_DIR / "data" / "common_passwords.txt"
)


# ============================================================
# COMMON PASSWORDS
# ============================================================

def load_common_passwords():

    if not COMMON_PASSWORD_FILE.exists():
        return set()

    with open(
        COMMON_PASSWORD_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return {
            line.strip().lower()
            for line in file
            if line.strip()
        }


# ============================================================
# REPEATED SUBSTRING DETECTION
# ============================================================

def detect_repeated_substring(password):

    text = password.lower()

    for size in range(
        2,
        len(text) // 2 + 1
    ):

        for start in range(
            len(text) - (size * 2) + 1
        ):

            first = text[
                start:start + size
            ]

            second = text[
                start + size:
                start + (size * 2)
            ]

            if first == second:
                return True

    return False


# ============================================================
# SEQUENCE DETECTION
# ============================================================

def detect_sequences(password):

    text = password.lower()

    sequences = [

        "0123",
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",

        "9876",
        "8765",
        "7654",
        "6543",

        "abcd",
        "bcde",
        "cdef",

        "dcba",
        "edcb",
        "fedc"

    ]

    return any(
        sequence in text
        for sequence in sequences
    )


# ============================================================
# KEYBOARD PATTERN DETECTION
# ============================================================

def detect_keyboard_pattern(password):

    text = password.lower()

    keyboard_patterns = [

        "qwerty",
        "asdf",
        "zxcv",
        "qwerty123",
        "asdfgh",

        "qaz",
        "wsx",
        "edc",

        "qwert",
        "werty",
        "asdfg"

    ]

    return any(
        pattern in text
        for pattern in keyboard_patterns
    )


# ============================================================
# PREDICTABLE STRUCTURE DETECTION
# ============================================================

def detect_predictable_structure(password):

    text = password.lower()

    predictable_words = [

        "password",
        "welcome",
        "admin",
        "hello",
        "login",
        "user",
        "guest",
        "test"

    ]

    for word in predictable_words:

        if text.startswith(word):

            remaining = text[len(word):]

            if remaining == "":
                continue

            if remaining.isdigit():
                return True

            if re.fullmatch(
                r"(19|20)\d{2}",
                remaining
            ):
                return True

    return False


# ============================================================
# ENTROPY ESTIMATION
# ============================================================

def estimate_entropy(password):

    if not password:
        return 0

    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"\d", password):
        pool_size += 10

    if re.search(
        r"[^A-Za-z0-9]",
        password
    ):
        pool_size += 32

    if pool_size == 0:
        return 0

    entropy = (
        len(password)
        * math.log2(pool_size)
    )

    return round(entropy, 2)


# ============================================================
# PASSWORD POLICY
# ============================================================

def check_password_policy(password):

    policy = {

        "minimum_length":
            len(password) >= 12,

        "maximum_length":
            len(password) <= 128,

        "has_lowercase":
            bool(re.search(
                r"[a-z]",
                password
            )),

        "has_uppercase":
            bool(re.search(
                r"[A-Z]",
                password
            )),

        "has_digit":
            bool(re.search(
                r"\d",
                password
            )),

        "has_symbol":
            bool(re.search(
                r"[^A-Za-z0-9]",
                password
            ))

    }

    policy["passed"] = all(
        policy.values()
    )

    return policy


# ============================================================
# MAIN PASSWORD ANALYZER
# ============================================================

def analyze_password(password):

    # Make sure password is a string
    if not isinstance(password, str):
        password = ""


    # --------------------------------------------------------
    # EMPTY PASSWORD
    # --------------------------------------------------------

    if len(password) == 0:

        return {

            "score": 0,

            "classification":
                "VERY WEAK",

            "findings": [
                "Password is empty."
            ],

            "suggestions": [
                "Enter a password to analyze."
            ],

            "metrics": {

                "length": 0,

                "lowercase": False,

                "uppercase": False,

                "digits": False,

                "symbols": False,

                "unique_characters": 0,

                "unique_ratio": 0,

                "entropy": 0

            },

            "policy":
                check_password_policy("")

        }


    # --------------------------------------------------------
    # INITIAL VALUES
    # --------------------------------------------------------

    findings = []

    suggestions = []

    score = 0

    length = len(password)


    # --------------------------------------------------------
    # CHARACTER TYPES
    # --------------------------------------------------------

    has_lower = bool(
        re.search(r"[a-z]", password)
    )

    has_upper = bool(
        re.search(r"[A-Z]", password)
    )

    has_digit = bool(
        re.search(r"\d", password)
    )

    has_symbol = bool(
        re.search(
            r"[^A-Za-z0-9]",
            password
        )
    )


    character_types = sum([

        has_lower,

        has_upper,

        has_digit,

        has_symbol

    ])


    # ========================================================
    # LENGTH SCORE
    # ========================================================

    if length < 8:

        score += 5

        findings.append(
            "Password is very short."
        )

        suggestions.append(
            "Use at least 12 characters."
        )

    elif length < 12:

        score += 20

        findings.append(
            "Password could be longer."
        )

        suggestions.append(
            "Make the password longer."
        )

    elif length < 16:

        score += 35

    else:

        score += 45


    # ========================================================
    # CHARACTER TYPE SCORE
    # ========================================================

    score += character_types * 8


    if not has_lower:

        suggestions.append(
            "Add lowercase letters."
        )


    if not has_upper:

        suggestions.append(
            "Add uppercase letters."
        )


    if not has_digit:

        suggestions.append(
            "Add numbers."
        )


    if not has_symbol:

        suggestions.append(
            "Add symbols."
        )


    # ========================================================
    # UNIQUE CHARACTER SCORE
    # ========================================================

    unique_characters = len(
        set(password)
    )

    unique_ratio = (
        unique_characters / length
    )


    if unique_ratio >= 0.75:

        score += 15

    elif unique_ratio >= 0.50:

        score += 8

    else:

        findings.append(
            "Password contains many repeated characters."
        )

        suggestions.append(
            "Use a greater variety of characters."
        )

        score -= 5


    # ========================================================
    # REPEATED CHARACTER DETECTION
    # ========================================================

    if re.search(
        r"(.)\1\1",
        password
    ):

        findings.append(
            "Password contains repeated characters."
        )

        suggestions.append(
            "Avoid repeating the same character many times."
        )

        score -= 10


    # ========================================================
    # REPEATED SUBSTRING
    # ========================================================

    if detect_repeated_substring(password):

        findings.append(
            "Password contains a repeated substring."
        )

        suggestions.append(
            "Avoid repeating patterns such as abcabc."
        )

        score -= 10


    # ========================================================
    # SEQUENCE DETECTION
    # ========================================================

    if detect_sequences(password):

        findings.append(
            "Password contains a sequential pattern."
        )

        suggestions.append(
            "Avoid sequences such as 1234 or abcd."
        )

        score -= 15


    # ========================================================
    # KEYBOARD PATTERN
    # ========================================================

    if detect_keyboard_pattern(password):

        findings.append(
            "Password contains a keyboard pattern."
        )

        suggestions.append(
            "Avoid keyboard patterns such as qwerty."
        )

        score -= 15


    # ========================================================
    # COMMON PASSWORD CHECK
    # ========================================================

    common_passwords = (
        load_common_passwords()
    )


    if password.lower() in common_passwords:

        findings.append(
            "Password appears in the common-password list."
        )

        suggestions.append(
            "Choose a unique password that is not commonly used."
        )

        score -= 30


    # ========================================================
    # PREDICTABLE STRUCTURE
    # ========================================================

    if detect_predictable_structure(password):

        findings.append(
            "Password uses a predictable word-and-number structure."
        )

        suggestions.append(
            "Avoid predictable combinations such as word + number or year."
        )

        score -= 15


    # ========================================================
    # ENTROPY
    # ========================================================

    entropy = estimate_entropy(
        password
    )


    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = max(
        0,
        min(
            100,
            score
        )
    )


    # ========================================================
    # CLASSIFICATION
    # ========================================================

    if score <= 20:

        classification = (
            "VERY WEAK"
        )

    elif score <= 40:

        classification = (
            "WEAK"
        )

    elif score <= 60:

        classification = (
            "MODERATE"
        )

    elif score <= 80:

        classification = (
            "STRONG"
        )

    else:

        classification = (
            "VERY STRONG"
        )


    # ========================================================
    # DEFAULT FINDING
    # ========================================================

    if not findings:

        findings.append(
            "No major weaknesses detected."
        )


    # ========================================================
    # DEFAULT SUGGESTION
    # ========================================================

    if not suggestions:

        suggestions.append(
            "Continue using unique passwords and enable MFA."
        )


    # ========================================================
    # PASSWORD POLICY
    # ========================================================

    policy = check_password_policy(
        password
    )


    # ========================================================
    # RETURN RESULT
    # ========================================================

    return {

        "score":
            score,

        "classification":
            classification,

        "findings":
            findings,

        "suggestions":
            suggestions,

        "metrics": {

            "length":
                length,

            "lowercase":
                has_lower,

            "uppercase":
                has_upper,

            "digits":
                has_digit,

            "symbols":
                has_symbol,

            "unique_characters":
                unique_characters,

            "unique_ratio":
                round(
                    unique_ratio,
                    2
                ),

            "entropy":
                entropy

        },

        "policy":
            policy

    }