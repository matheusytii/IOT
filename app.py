# app.py
import os
import io
import base64
import time
from threading import Thread, Event
from datetime import datetime

import requests
import pyotp
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from pymongo import MongoClient

# -------------------------
# Configuração do App
# -------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("APP_SECRET", "replace-with-a-secure-random-secret-in-production")

# -------------------------
# Configuração ThingSpeak
# -------------------------
THINGSPEAK_CHANNEL_ID = os.getenv("THINGSPEAK_CHANNEL_ID", "3092047")
THINGSPEAK_READ_KEY = os.getenv("THINGSPEAK_READ_KEY", "FAAOZXTN40Q8J8M9")
THINGSPEAK_URL = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/fields/1.json"

# -------------------------
# Configuração MongoDB
MONGO_URI = os.getenv("MONGO_URI", 
    "mongodb+srv://matheusyti:86fPMDewQFS1zlri@cluster0.nplf7ye.mongodb.net/iot_dashboard?retryWrites=true&w=majority&appName=Cluster0"
)

DB_NAME = os.getenv("DB_NAME", "iot_dashboard")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "mq2_readings")


# Inicialização do Cliente e Variável de Controle da Thread
time.sleep(0.5)
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client[DB_NAME]
    collection = db[COLLECTION_NAME]
    mongo_client.server_info()
    print(f" -> ✅ Conectado ao MongoDB em: {MONGO_URI} (DB: {DB_NAME}, Collection: {COLLECTION_NAME})")
except Exception as e:
    print(f" -> ❌ AVISO: Não foi possível conectar ao MongoDB: {e}")
    collection = None

# Variável global para controlar a thread de sincronização
stop_sync_event = Event()

# -------------------------
# Armazenamento de Usuários (Memória)
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
# Helpers e Filtros
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
        if isinstance(s, str) and s.endswith('Z'):
            dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        elif isinstance(s, str):
            dt = datetime.fromisoformat(s)
        elif isinstance(s, datetime):
            dt = s
        else:
            return str(s)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(s)

# -------------------------
# FUNÇÃO CENTRAL DE SINCRONIZAÇÃO
# -------------------------
def perform_sync_operation():
    """Lê os dados do ThingSpeak e salva/atualiza no MongoDB Atlas."""
    if collection is None:
        return {"error": "MongoDB não conectado ou inacessível"}

    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=100"
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"error": f"Falha ao ler ThingSpeak (Status: {response.status_code})"}

        feeds = response.json().get("feeds", [])
        upserted_count = 0
        modified_count = 0

        for item in feeds:
            entry_id_raw = item.get("entry_id")
            val_str = item.get("field1")
            created_at = item.get("created_at")

            if entry_id_raw is None:
                continue

            # sanitize entry_id
            try:
                entry_id = int(entry_id_raw)
            except Exception:
                # pula entry_id inválido
                continue

            # ajusta valor do campo se for nulo ou vazio
            if val_str is None or str(val_str).strip() == "":
                continue

            try:
                gas_value = float(val_str)
            except Exception:
                continue

            doc = {
                "entry_id": entry_id,
                "timestamp_ts": created_at,
                "gas_value": gas_value,
                "synced_at": datetime.utcnow()
            }

            result = collection.update_one({"entry_id": entry_id}, {"$set": doc}, upsert=True)
            # resultado.upserted_id existe somente quando inseriu
            if getattr(result, "upserted_id", None):
                upserted_count += 1
            # modified_count indica atualizações (pode ser 0 se upsert sem modificação)
            if result.modified_count:
                modified_count += 1

        total = collection.count_documents({})
        return {
            "status": "Sincronizado com sucesso!",
            "fetched": len(feeds),
            "new_inserted": upserted_count,
            "updated": modified_count,
            "total_in_db": total
        }

    except Exception as e:
        return {"error": str(e)}

# -------------------------
# THREAD DE SINCRONIZAÇÃO EM BACKGROUND
# -------------------------
def sync_background_thread(interval_seconds=60):
    print(f"--- 🟢 Thread de Sincronização Iniciada (intervalo {interval_seconds}s) ---")
    time.sleep(2)
    while not stop_sync_event.is_set():
        if stop_sync_event.wait(interval_seconds):
            break
        with app.app_context():
            result = perform_sync_operation()
            log_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            if "error" in result:
                print(f"[{log_time}] -> ❌ Erro na Sincronização: {result['error']}")
            else:
                print(f"[{log_time}] -> ✅ Sincronização: fetched={result['fetched']} inserted={result['new_inserted']} updated={result['updated']} total={result['total_in_db']}")
    print("--- 🔴 Thread de Sincronização Parada ---")

# -------------------------
# ROTAS FLASK & AUTENTICAÇÃO (simples)
# -------------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("username") and session.get("mfa_validated")):
            flash("Acesso negado. Faça login e valide o MFA.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

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
        if not username or not password or username in users:
            flash("Erro no registro ou usuário já existe.", "danger")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        secret = pyotp.random_base32()
        users[username] = {
            "password": hashed,
            "mfa_secret": secret,
            "registered_at": datetime.utcnow().isoformat(),
            "last_login": None, "login_count": 0, "logged_in": False
        }
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskMFA-IoT")
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
            user["last_login"] = datetime.utcnow().isoformat()
            user["login_count"] = user.get("login_count", 0) + 1
            user["logged_in"] = True
            flash("Autenticação validada com sucesso!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Código inválido. Tente novamente.", "danger")
            return redirect(url_for("mfa_verify"))
    return render_template("mfa_verify.html", username=username)

@app.route("/logout")
def logout():
    username = session.get("username")
    if username and username in users:
        users[username]["logged_in"] = False
    session.clear()
    flash("Desconectado.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    mongo_count = 0
    last_synced_time = "Nunca"
    if collection is not None:
        try:
            mongo_count = collection.count_documents({})
            last_doc = collection.find_one(sort=[("timestamp_ts", -1)])
            if last_doc:
                last_synced_time = shorttime(last_doc.get("timestamp_ts"))
        except Exception:
            mongo_count = "Erro"
    return render_template("dashboard.html",
                           total_users=len(users),
                           active_sessions=sum(1 for u in users.values() if u.get("logged_in")),
                           recent=sorted(users.items(), key=lambda kv: kv[1].get("last_login") or "", reverse=True)[:5],
                           users=users,
                           mongo_count=mongo_count,
                           last_synced_time=last_synced_time)

@app.route("/mq2")
@login_required
def mq2_page():
    return render_template("mq2.html")

@app.route("/api/mq2/latest")
@login_required
def get_latest_mq2():
    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=1"
        response = requests.get(url, timeout=6)
        if response.status_code != 200:
            return jsonify({"error": "Erro ao acessar ThingSpeak"}), 500
        feed = response.json().get("feeds", [])
        if not feed or feed[0].get("field1") is None:
            return jsonify({"error": "Nenhum dado disponível"}), 404
        return jsonify({
            "gas_value": feed[0].get("field1"),
            "timestamp": shorttime(feed[0].get("created_at"))
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sync-mongo", methods=["POST", "GET"])
@login_required
def sync_mongo():
    result = perform_sync_operation()
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)

@app.route("/api/mq2/graph-data")
@login_required
def mq2_graph_data():
    if collection is None:
        return jsonify({"error": "MongoDB indisponível"}), 500
    try:
        cursor = collection.find({}, {"_id": 0, "timestamp_ts": 1, "gas_value": 1}).sort("entry_id", 1).limit(100)
        timestamps = []
        values = []
        for item in cursor:
            timestamps.append(item.get("timestamp_ts"))
            values.append(item.get("gas_value"))
        return jsonify({"labels": timestamps, "values": values})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    mongo_ok = collection is not None
    return jsonify({"ok": True, "mongo_connected": mongo_ok})

# -----------------------------------------------------
# EXECUÇÃO FINAL
# -----------------------------------------------------
if __name__ == "__main__":
    # Sincronização inicial (popula o banco)
    print("-----------------------------------------------------")
    print("--- ⚙️ Sincronização Inicial Única ---")
    sync_result = perform_sync_operation()
    if "error" in sync_result:
        print(f"-> ❌ FALHA na Sincronização Inicial: {sync_result['error']}")
    else:
        print(f"-> ✅ Sincronização Inicial CONCLUÍDA: Inseridos {sync_result['new_inserted']} / Total no DB: {sync_result['total_in_db']}")
    print("-----------------------------------------------------")

    # Inicia thread de sincronização periódica
    sync_thread = Thread(target=sync_background_thread, kwargs={"interval_seconds": 60}, daemon=True)
    sync_thread.start()

    try:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True, use_reloader=False)
    finally:
        stop_sync_event.set()
        sync_thread.join()
