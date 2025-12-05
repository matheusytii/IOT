# Flask MFA v2 — UI Melhorada + Dashboard com MQ-2

Este projeto é uma aplicação Flask com autenticação MFA (TOTP) integrada, UI aprimorada com Bootstrap, sistema de registro/login, além de um dashboard completo com estatísticas e uma página dedicada ao sensor MQ-2 (simulado).

A aplicação foi desenvolvida para ser simples de executar localmente e também totalmente compatível com deploy no Render via gunicorn.

---

## 🌐 Deploy Online

A aplicação já está **disponível e online no Render**:

👉 **https://iot-9d38.onrender.com/**  

---

## 📁 Estrutura do Projeto

IOT-main/  
│  
├── app.py                — Aplicação Flask principal  
├── requirements.txt      — Dependências da aplicação  
├── render.yaml           — Configuração para deploy no Render  
├── static/  
│   └── styles.css        — Estilos adicionais da interface  
├── templates/  
│   ├── base.html         — Template principal com Bootstrap  
│   ├── login.html        — Login e autenticação  
│   ├── register.html     — Registro de usuário  
│   ├── mfa_setup.html    — Configuração do TOTP (QRCode)  
│   ├── mfa_verify.html   — Validação MFA  
│   ├── dashboard.html    — Dashboard com estatísticas  
│   └── mq2.html          — Página dedicada ao sensor MQ-2  
└── README.md

---

## 🚀 Funcionalidades Principais

### 🔐 Autenticação com MFA (TOTP)
- Login tradicional (usuário e senha).  
- Etapa extra de verificação por código TOTP (Google Authenticator, Authy, etc.).  
- QRCode gerado automaticamente na página de configuração MFA.

### 👤 Sistema de Usuários
- Registro simples.  
- Usuário demo pré-criado:  
  - usuário: **demo**  
  - senha: **password**

### 📊 Dashboard
- Interface construída com Bootstrap.  
- Gráficos e dados simulados sobre:  
  - atividades do sistema  
  - últimos acessos  
  - eventos do MQ-2  

### 🌡️ Página MQ-2
- Tela dedicada para exibição de níveis simulados de fumaça/gás.  
- Atualização gerada via backend.

### 💾 Armazenamento
- A aplicação usa armazenamento em memória (dict).  
- Para produção, recomenda-se trocar por:  
  - SQLite  
  - PostgreSQL  
  - MySQL  
  - MongoDB  

---

## 🖥️ Como rodar localmente

### 1️⃣ Criar ambiente virtual
```
python3 -m venv venv
```

### 2️⃣ Ativar ambiente
Linux / macOS:
```
source venv/bin/activate
```
Windows:
```
venv\Scripts\activate
```

### 3️⃣ Instalar dependências
```
pip install -r requirements.txt
```

### 4️⃣ Definir variáveis de ambiente
```
export APP_SECRET='uma_senha_secreta'
```

### 5️⃣ Rodar a aplicação
```
python app.py
```

➡️ Acesse em:  
http://localhost:5000

---

## 📦 Deploy no Render

A aplicação já está configurada para deploy no Render.

### Comando de start:
```
gunicorn --bind 0.0.0.0:$PORT app:app
```

### Arquivo `render.yaml` incluído:
Define:
- build  
- comando de start  
- versão do Python  
- variáveis de ambiente necessárias  

---

## ⚙️ Variáveis Necessárias

| Variável     | Descrição                           |
|--------------|-------------------------------------|
| APP_SECRET   | Segredo interno da aplicação (obrigatório) |

Use um segredo forte no Render:

```
openssl rand -hex 32
```

---

## 📝 Observações importantes
- O banco de dados é apenas em memória — ao reiniciar, os dados somem.  
- Estrutura preparada para expansão futura:  
  - banco real  
  - mais dashboards  
  - integração com MQ-2 real  

---

## 📚 Tecnologias Usadas
- Python 3  
- Flask  
- PyOTP  
- Qrcode  
- Bootstrap 5  
- Gunicorn  
- Render  

---

## 👩‍💻 Autores
Aplicação criada e estruturada por:

- Antônio Vinícius de Lima Campos  
- Douglas Lucas da Silva Filho  
- Irene Eloyse Lopes Miranda  
- João Vitor Souza Lopes  
- Jordy Inácio Arlego Barcelo dos Santos  
- Maria Luiza Barbosa de Oliveira  
- Matheus Ramos do Carmo  
