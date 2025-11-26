Flask MFA v2 — UI melhorada e Dashboard
======================================

Conteúdo:
 - app.py: aplicação Flask com MFA (TOTP) e dashboard com estatísticas.
 - templates/: base, páginas e dashboard com Bootstrap.
 - static/styles.css: estilos adicionais.
 - requirements.txt
 - render.yaml

Como rodar localmente:
1. python3 -m venv venv
2. source venv/bin/activate
3. pip install -r requirements.txt
4. export APP_SECRET='uma_senha_secreta'
5. python app.py

Start com gunicorn (Render):
gunicorn --bind 0.0.0.0:$PORT app:app

Observações:
- Este projeto usa armazenamento em memória (dict). Para produção, substitua por um banco de dados.
- O usuário demo: demo / password — já pré-criado para testar rapidamente.
- Substitua APP_SECRET por um segredo forte no ambiente do Render.