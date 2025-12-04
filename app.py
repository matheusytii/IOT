import os
import io
import base64
from datetime import datetime

import requests
import pyotp
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

# -------------------------
# App config
# -------------------------
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "replace-with-a-secure-random-secret-in-production")

# -------------------------
# In-memory user store (demo)
# -------------------------
users = {
    "demo": {
        "password": generate_password_hash("password"),
        "mfa_secret": pyotp.random_base32(),
        "registered_at": datetime.utcnow().isoformat(),
        "last_login": None,
        "login_count": 0,
        "logged_in": False
    }
}

# -------------------------
# Helpers
# -------------------------
def qrcode_data_uri(data):
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return "data:image/png;base64," + b64

@app.template_filter('shorttime')
def shorttime(s):
    if not s:
        return "—"
    try:
        dt = datetime.fromisoformat(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return s

# -------------------------
# ThingSpeak configuration
# -------------------------
THINGSPEAK_URL = "https://api.thingspeak.com/channels/3092047/fields/1.json"
THINGSPEAK_READ_KEY = "FAAOZXTN40Q8J8M9"   # sua read key, mantenha segura

# -------------------------
# Auth / MFA routes
# -------------------------
@app.route("/")
def index():
    if session.get("username") and session.get("mfa_validated"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Usuário e senha são obrigatórios.", "danger")
            return redirect(url_for("register"))
        if username in users:
            flash("Usuário já existe.", "warning")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        secret = pyotp.random_base32()
        users[username] = {
            "password": hashed,
            "mfa_secret": secret,
            "registered_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "login_count": 0,
            "logged_in": False
        }
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskMFA-Render")
        img_uri = qrcode_data_uri(uri)
        return render_template("mfa_setup.html", img_uri=img_uri, secret=secret, username=username)
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = users.get(username)
        if not user or not check_password_hash(user["password"], password):
            flash("Usuário ou senha inválidos.", "danger")
            return redirect(url_for("login"))
        session["username"] = username
        session["mfa_validated"] = False
        return redirect(url_for("mfa_verify"))
    return render_template("login.html")

@app.route("/mfa_verify", methods=["GET", "POST"])
def mfa_verify():
    username = session.get("username")
    if not username:
        flash("Faça login primeiro.", "warning")
        return redirect(url_for("login"))
    user = users.get(username)
    if request.method == "POST":
        code = request.form["code"].strip()
        totp = pyotp.TOTP(user["mfa_secret"])
        if totp.verify(code, valid_window=1):
            session["mfa_validated"] = True
            # update user stats
            user["last_login"] = datetime.utcnow().isoformat()
            user["login_count"] = user.get("login_count", 0) + 1
            user["logged_in"] = True
            flash("Autenticação por MFA validada com sucesso!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Código inválido. Tente novamente.", "danger")
            return redirect(url_for("mfa_verify"))
    return render_template("mfa_verify.html", username=username)

@app.route("/dashboard")
def dashboard():
    if not (session.get("username") and session.get("mfa_validated")):
        flash("Acesso negado. Faça login e valide o MFA.", "warning")
        return redirect(url_for("login"))
    # Build stats
    total_users = len(users)
    active_sessions = sum(1 for u in users.values() if u.get("logged_in"))
    recent = sorted(users.items(), key=lambda kv: kv[1].get("last_login") or "", reverse=True)[:5]
    return render_template("dashboard.html", total_users=total_users, active_sessions=active_sessions, recent=recent, users=users)

@app.route("/logout")
def logout():
    username = session.get("username")
    if username and username in users:
        users[username]["logged_in"] = False
    session.clear()
    flash("Desconectado.", "info")
    return redirect(url_for("index"))

# -------------------------
# Simple API endpoint for quick stats (optional)
# -------------------------
@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_users": len(users),
        "active_sessions": sum(1 for u in users.values() if u.get("logged_in")),
        "timestamp": datetime.utcnow().isoformat()
    })

# -------------------------
# ThingSpeak endpoints (MQ-2)
# -------------------------
@app.route("/api/mq2/latest")
def get_latest_mq2():
    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=1"
        response = requests.get(url, timeout=6)
        if response.status_code != 200:
            return jsonify({"error": "Erro ao acessar ThingSpeak", "status": response.status_code}), 500
        feed = response.json().get("feeds", [])
        if not feed:
            return jsonify({"error": "Nenhum dado disponível"}), 404
        last = feed[0]
        return jsonify({
            "gas_value": last.get("field1"),
            "timestamp": last.get("created_at")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/mq2/history")
def get_history_mq2():
    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=100"
        response = requests.get(url, timeout=8)
        if response.status_code != 200:
            return jsonify({"error": "Erro ao acessar ThingSpeak", "status": response.status_code}), 500
        data = response.json().get("feeds", [])
        history = []
        for item in data:
            history.append({
                "gas_value": item.get("field1"),
                "timestamp": item.get("created_at")
            })
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------------
# Page that shows MQ-2 (only after MFA)
# -------------------------
@app.route("/mq2")
def mq2_page():
    if not (session.get("username") and session.get("mfa_validated")):
        flash("Faça login e valide o MFA.", "danger")
        return redirect(url_for("login"))
    return render_template("mq2.html")

@app.route("/api/mq2/graph-data")
def mq2_graph_data():
    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=50"
        response = requests.get(url, timeout=8)

        if response.status_code != 200:
            return jsonify({"error": "Erro ao acessar ThingSpeak"}), 500

        data = response.json().get("feeds", [])

        timestamps = []
        values = []

        for item in data:
            v = item.get("field1")
            if v is None:
                continue
            try:
                v = float(v)
            except:
                continue

            timestamps.append(item.get("created_at"))
            values.append(v)

        return jsonify({
            "labels": timestamps,
            "values": values
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------------
# Run app (dev). For Render/Gunicorn remove this block.
# -------------------------
if __name__ == "__main__":
    # modo dev com reload
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
