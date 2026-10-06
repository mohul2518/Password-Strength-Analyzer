from flask import Flask, request, jsonify, send_from_directory
from pathlib import Path

from password_analyzer import analyze_password
from password_generator import generate_password


# Create Flask application
app = Flask(__name__)

# Path to frontend folder
BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_FOLDER = BASE_DIR / "frontend"


# -----------------------------
# HOME PAGE
# -----------------------------
@app.route("/")
def home():
    return send_from_directory(FRONTEND_FOLDER, "index.html")


# -----------------------------
# FRONTEND FILES
# -----------------------------
@app.route("/<path:filename>")
def frontend_files(filename):
    return send_from_directory(FRONTEND_FOLDER, filename)


# -----------------------------
# PASSWORD ANALYZER API
# -----------------------------
@app.route("/api/analyze", methods=["POST"])
def analyze():

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No data received."
            }), 400

        password = data.get("password", "")

        result = analyze_password(password)

        return jsonify(result)

    except Exception as error:

        print("ANALYZER ERROR:", error)

        return jsonify({
            "error": "An error occurred while analyzing the password."
        }), 500


# -----------------------------
# PASSWORD GENERATOR API
# -----------------------------
@app.route("/api/generate-password", methods=["POST"])
def generate():

    try:

        data = request.get_json() or {}

        length = data.get("length", 16)

        try:
            length = int(length)
        except (ValueError, TypeError):
            length = 16

        # Keep generator length within safe limits
        if length < 12:
            length = 12

        if length > 128:
            length = 128

        password = generate_password(length)

        return jsonify({
            "password": password,
            "length": length
        })

    except Exception as error:

        print("GENERATOR ERROR:", error)

        return jsonify({
            "error": "Could not generate password."
        }), 500


# -----------------------------
# START SERVER
# -----------------------------
if __name__ == "__main__":

    print("----------------------------------------")
    print("Password Strength Analyzer")
    print("----------------------------------------")
    print("Open this address in your browser:")
    print("http://127.0.0.1:5000/")
    print("----------------------------------------")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
    