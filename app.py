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
app = Flask(__name__)
# Usando Tailwind para estilos, que será incluído no HTML
app.secret_key = os.getenv("APP_SECRET", "replace-with-a-secure-random-secret-in-production")

# -------------------------
# Configuração ThingSpeak
# -------------------------
THINGSPEAK_CHANNEL_ID = "3092047"
THINGSPEAK_READ_KEY = "FAAOZXTN40Q8J8M9"
THINGSPEAK_URL = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/fields/1.json"

# -------------------------
# Configuração MongoDB (Com a sua nova senha)
# -------------------------
MONGO_URI = f"mongodb+srv://matheusyti:bWaTalqedtLHBQYW@cluster0.nplf7ye.mongodb.net/?appName=Cluster0"

# Inicialização do Cliente e Variável de Controle da Thread
time.sleep(1) 
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client["iot_dashboard"]       
    collection = db["mq2_readings"]          
    mongo_client.server_info()
    print(f" -> ✅ Conectado ao MongoDB em: {MONGO_URI}")
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
    """Gera um QR code como Data URI (base64)."""
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return "data:image/png;base64," + b64

@app.template_filter('shorttime')
def shorttime(s):
    """Formata a string de timestamp ISO para um formato legível."""
    if not s:
        return "—"
    try:
        # Lidar com o formato ThingSpeak (termina em 'Z')
        if s.endswith('Z'):
            dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        else:
            # Lidar com o formato de data ISO normal
            dt = datetime.fromisoformat(s)
        # Retorna a data/hora formatada
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return s

# -------------------------
# FUNÇÃO CENTRAL DE SINCRONIZAÇÃO
# -------------------------
def perform_sync_operation():
    """Lê os dados do ThingSpeak e salva/atualiza no MongoDB Atlas."""
    if collection is None:
        return {"error": "MongoDB não conectado ou inacessível"}

    try:
        # Lê os últimos 100 feeds para garantir que o histórico recente seja sincronizado
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=100"
        response = requests.get(url, timeout=10)
        
        if response.status_code != 200:
            return {"error": f"Falha ao ler ThingSpeak (Status: {response.status_code})"}

        feeds = response.json().get("feeds", [])
        upserted_count = 0
        modified_count = 0

        for item in feeds:
            entry_id = item.get("entry_id")
            val_str = item.get("field1")
            
            if val_str is None or entry_id is None:
                continue

            # Converte o valor do gás para float
            try:
                gas_value = float(val_str)
            except ValueError:
                continue # Pula se o valor não for numérico

            doc = {
                "entry_id": entry_id,
                "timestamp_ts": item.get("created_at"),
                "gas_value": gas_value,
                "synced_at": datetime.utcnow()
            }

            # Usa entry_id como chave única para upsert (atualiza ou insere)
            result = collection.update_one(
                {"entry_id": entry_id}, 
                {"$set": doc}, 
                upsert=True
            )
            
            if result.upserted_id:
                upserted_count += 1
            if result.modified_count:
                modified_count += 1

        return {
            "status": "Sincronizado com sucesso!",
            "fetched": len(feeds),
            "new_inserted": upserted_count,
            "updated": modified_count,
            "total_in_db": collection.count_documents({})
        }

    except Exception as e:
        return {"error": str(e)}

# -------------------------
# THREAD DE SINCRONIZAÇÃO EM BACKGROUND
# -------------------------
def sync_background_thread(interval_seconds=60):
    """Roda a sincronização a cada X segundos em uma thread separada."""
    print(f"--- 🟢 Thread de Sincronização em Background Iniciada (Intervalo: {interval_seconds}s) ---")
    
    # Adiciona um pequeno delay no loop inicial para não conflitar com o startup
    time.sleep(5) 
    
    while not stop_sync_event.is_set():
        if stop_sync_event.wait(interval_seconds):
            break 
            
        with app.app_context(): # Necessário para acessar as variáveis globais do Flask (como o banco de dados)
            result = perform_sync_operation()
            log_time = datetime.now().strftime("%H:%M:%S")
            
            if "error" in result:
                print(f"[{log_time}] -> ❌ Erro na Sincronização Automática: {result['error']}")
            else:
                print(f"[{log_time}] -> ✅ Sincronização Periódica: Inseridos {result['new_inserted']} / Atualizados {result['updated']} / Total no DB: {result['total_in_db']}")
    
    print("--- 🔴 Thread de Sincronização Parada. ---")


# -------------------------
# ROTAS FLASK
# -------------------------

def login_required(f):
    """Decorator para exigir autenticação completa."""
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
    # Stats MongoDB para o Dashboard
    mongo_count = 0
    last_synced_time = "Nunca"
    if collection is not None:
        try:
            mongo_count = collection.count_documents({})
            # Busca o último documento sincronizado, ordenando pelo timestamp do ThingSpeak
            last_doc = collection.find_one(sort=[("timestamp_ts", -1)])
            if last_doc:
                last_synced_time = shorttime(last_doc.get("timestamp_ts"))
        except:
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
    """Busca o último dado diretamente do ThingSpeak (tempo real)."""
    try:
        url = f"{THINGSPEAK_URL}?api_key={THINGSPEAK_READ_KEY}&results=1"
        response = requests.get(url, timeout=5)
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
    """Força a sincronização manual (para testes)."""
    result = perform_sync_operation()
    
    if "error" in result:
        return jsonify(result), 500 
    
    return jsonify(result)

@app.route("/api/mq2/graph-data")
@login_required
def mq2_graph_data():
    """Retorna o histórico de dados do MongoDB (para gráficos)."""
    if collection is None:
        return jsonify({"error": "MongoDB indisponível"}), 500

    try:
        # Busca os últimos 100 documentos, ordenados por entry_id (que deve ser cronológico)
        cursor = collection.find({}, {"_id": 0, "timestamp_ts": 1, "gas_value": 1}).sort("entry_id", 1).limit(100)
        
        timestamps = []
        values = []
        
        for item in cursor:
            # Garante que o timestamp seja formatado corretamente e o valor seja um número
            timestamps.append(shorttime(item.get("timestamp_ts")))
            values.append(item.get("gas_value"))

        # Retorna a estrutura {labels: [...], values: [...]} que o frontend espera
        return jsonify({
            "labels": timestamps,
            "values": values
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------
# EXECUÇÃO FINAL
# -----------------------------------------------------
if __name__ == "__main__":
    # 1. Executa a sincronização uma vez no startup (para popular o banco)
    print("-----------------------------------------------------")
    print("--- ⚙️ Sincronização Inicial Única ---")
    sync_result = perform_sync_operation()
    
    if "error" in sync_result:
        print(f"-> ❌ FALHA na Sincronização Inicial: {sync_result['error']}")
    else:
        print(f"-> ✅ Sincronização Inicial CONCLUÍDA: Inseridos {sync_result['new_inserted']} / Total no DB: {sync_result['total_in_db']}")
        
    print("-----------------------------------------------------")

    # 2. Inicia a thread de sincronização periódica (mantém o banco atualizado)
    sync_thread = Thread(target=sync_background_thread, daemon=True)
    sync_thread.start()
    
    # 3. Inicia o servidor web Flask COM RECARREGADOR DESLIGADO (use_reloader=False)
    # ESSENCIAL para evitar a duplicação da thread e do bug de login/registro
    try:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True, use_reloader=False)
    finally:
        # Garante que a thread seja parada ao desligar o servidor
        stop_sync_event.set()
        sync_thread.join()