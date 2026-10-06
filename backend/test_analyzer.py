from password_analyzer import analyze_password


passwords = [
    "123456",
    "Password123!",
    "qwerty2026!",
    "MyVeryStrongPassword!2026"
]

for password in passwords:
    result = analyze_password(password)

    print("\nPassword:", password)
    print("Score:", result["score"])
    print("Classification:", result["classification"])
    print("Findings:", result["findings"])
    print("Suggestions:", result["suggestions"])