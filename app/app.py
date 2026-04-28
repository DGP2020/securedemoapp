import os
from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# In a real app, this would be an environment variable
SECRET = os.environ.get("SECRET_KEY", "default-fallback-key")
# --- FIXED SECTION: Only one 'home' function allowed ---
@app.route("/")
def home():
    logging.info("Public endpoint accessed")
    return jsonify({
        "message": "App is working",
        "status": "App is running", 
        "auth": "None Required"
    })

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        return jsonify({"error": "Missing JSON in request"}), 400

    # Basic hardcoded check for demo purposes
    if data.get("username") == "admin" and data.get("password") == "admin":
        token = jwt.encode({
            "user": data.get("username"),
            "role": "admin" if data.get("username") == "admin" else "user",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        }, SECRET, algorithm="HS256")
        return jsonify({"token": token})
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/secure", methods=["GET"])
def secure():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return jsonify({"error": "Missing token"}), 401
    
    try:
        # Expecting "Bearer <token>"
        token = auth_header.split(" ")[1] 
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        if payload.get("role") != "admin":
            return jsonify({"error": "Forbidden: Admins only"}), 403
    except Exception as e:
        return jsonify({"error": "Unauthorized", "details": str(e)}), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)





