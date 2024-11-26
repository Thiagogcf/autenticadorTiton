from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
import json
import hashlib
import time
import os
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
# Adicione isso no início do seu arquivo app.py, ANTES de criar o objeto Flow
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Permite HTTP para desenvolvimento
app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app)

USERS_FILE = 'users.json'
CODES_FILE = 'active_codes.json'
IP_BLOCKS_FILE = 'ip_blocks.json'
MAX_ATTEMPTS = 5

BLOCK_TIMES = {
    1: 60,  
    2: 300,  
    3: 600,  
    4: 3600,  
    5: 86400  
}

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
GOOGLE_REDIRECT_URI = "http://127.0.0.1:5000/api/login/google/callback"

flow = Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=[
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
        'openid'
    ],
    redirect_uri=GOOGLE_REDIRECT_URI
)


def init_storage():
    files = {
        USERS_FILE: {
            "a@b.c": {
                "senha": hashlib.sha256("senha".encode()).hexdigest(),
                "bloqueado": False
            }
        },
        CODES_FILE: {},
        IP_BLOCKS_FILE: {}
    }

    for filename, default_data in files.items():
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                json.dump(default_data, f)


def load_data(filename):
    with open(filename, 'r') as f:
        return json.load(f)


def save_data(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f)


def get_ip_data(ip):
    ip_blocks = load_data(IP_BLOCKS_FILE)
    if ip not in ip_blocks:
        ip_blocks[ip] = {
            'attempts': 0,
            'block_level': 0,
            'block_until': 0
        }
        save_data(ip_blocks, IP_BLOCKS_FILE)
    return ip_blocks[ip]


def is_ip_blocked(ip):
    ip_data = get_ip_data(ip)
    if ip_data['block_until'] > time.time():
        return True, int(ip_data['block_until'] - time.time())
    return False, 0


def block_ip(ip):
    ip_blocks = load_data(IP_BLOCKS_FILE)
    ip_data = ip_blocks.get(ip, {
        'attempts': 0,
        'block_level': 0,
        'block_until': 0
    })

    
    if time.time() > ip_data['block_until']:
        block_level = 1
    else:
        block_level = min(ip_data['block_level'] + 1, 5)

    
    block_duration = BLOCK_TIMES[block_level]
    ip_blocks[ip] = {
        'attempts': 0,
        'block_level': block_level,
        'block_until': time.time() + block_duration
    }

    save_data(ip_blocks, IP_BLOCKS_FILE)
    return block_duration


def increment_attempts(ip):
    ip_blocks = load_data(IP_BLOCKS_FILE)
    ip_data = get_ip_data(ip)
    ip_data['attempts'] += 1
    ip_blocks[ip] = ip_data
    save_data(ip_blocks, IP_BLOCKS_FILE)

    
    if ip_data['attempts'] >= MAX_ATTEMPTS:
        return block_ip(ip)
    return None


def reset_attempts(ip):
    ip_blocks = load_data(IP_BLOCKS_FILE)
    if ip in ip_blocks:
        ip_blocks[ip]['attempts'] = 0
        save_data(ip_blocks, IP_BLOCKS_FILE)


def generate_2fa_code():
    current_time = datetime.now()
    time_hash = hashlib.sha256(str(current_time.timestamp()).encode()).hexdigest()
    return str(int(time_hash[:8], 16) % 900000 + 100000)


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        senha = data.get('senha')
        ip = request.remote_addr

        if not email or not senha:
            return jsonify({'erro': 'Email e senha são obrigatórios'}), 400

        
        blocked, remaining_time = is_ip_blocked(ip)
        if blocked:
            return jsonify({
                'erro': f'IP bloqueado por {remaining_time} segundos',
                'tentativas_restantes': 0
            }), 403

        
        users = load_data(USERS_FILE)
        user = users.get(email)

        if not user or user['senha'] != hashlib.sha256(senha.encode()).hexdigest():
            
            block_duration = increment_attempts(ip)
            ip_data = get_ip_data(ip)

            if block_duration:
                return jsonify({
                    'erro': f'IP bloqueado por {block_duration} segundos',
                    'tentativas_restantes': 0
                }), 403

            return jsonify({
                'erro': 'Credenciais inválidas',
                'tentativas_restantes': MAX_ATTEMPTS - ip_data['attempts']
            }), 401

        
        codigo = generate_2fa_code()
        codes = load_data(CODES_FILE)
        codes[email] = {
            'codigo': codigo,
            'expira_em': time.time() + 120
        }
        save_data(codes, CODES_FILE)

        
        reset_attempts(ip)

        print(f"Código 2FA para {email}: {codigo}")
        return jsonify({'mensagem': 'Código 2FA enviado'})

    except Exception as e:
        print(f"Erro no login: {str(e)}")
        return jsonify({'erro': 'Erro interno do servidor'}), 500


@app.route('/api/verificar-2fa', methods=['POST'])
def verify_2fa():
    try:
        data = request.json
        email = data.get('email')
        codigo = data.get('codigo')
        ip = request.remote_addr

        if not email or not codigo:
            return jsonify({'erro': 'Email e código são obrigatórios'}), 400

        
        blocked, remaining_time = is_ip_blocked(ip)
        if blocked:
            return jsonify({
                'erro': f'IP bloqueado por {remaining_time} segundos',
                'tentativas_restantes': 0
            }), 403

        codes = load_data(CODES_FILE)
        code_data = codes.get(email)

        if not code_data:
            return jsonify({'erro': 'Nenhum código ativo para este usuário'}), 400

        if time.time() > code_data['expira_em']:
            del codes[email]
            save_data(codes, CODES_FILE)
            return jsonify({'erro': 'Código expirado'}), 400

        if codigo != code_data['codigo']:
            
            block_duration = increment_attempts(ip)
            ip_data = get_ip_data(ip)

            if block_duration:
                return jsonify({
                    'erro': f'IP bloqueado por {block_duration} segundos',
                    'tentativas_restantes': 0
                }), 403

            return jsonify({
                'erro': 'Código inválido',
                'tentativas_restantes': MAX_ATTEMPTS - ip_data['attempts']
            }), 401

        
        del codes[email]
        save_data(codes, CODES_FILE)
        reset_attempts(ip)

        session['email'] = email
        session['logged_in'] = True
        session['last_activity'] = datetime.now().timestamp()

        return jsonify({
            'mensagem': 'Login realizado com sucesso',
            'token': 'jwt-token-simulado'
        })

    except Exception as e:
        print(f"Erro na verificação 2FA: {str(e)}")
        return jsonify({'erro': 'Erro interno do servidor'}), 500


@app.route('/api/login/google', methods=['GET'])
def login_google():
    authorization_url, state = flow.authorization_url()
    return jsonify({'url': authorization_url})


@app.route('/api/login/google/callback', methods=['GET'])
def login_google_callback():
    try:
        flow.fetch_token(authorization_response=request.url)

        if not flow.credentials:
            return jsonify({'erro': 'Falha na autenticação com o Google'}), 400

        # Cria uma nova instância do Request do Google
        google_request = google.auth.transport.requests.Request()

        # Verifica o token com a tolerância de tempo
        id_info = id_token.verify_oauth2_token(
            flow.credentials.id_token,
            google_request,
            clock_skew_in_seconds=10
        )

        if 'email' not in id_info:
            return jsonify({'erro': 'Email não encontrado nas informações do Google'}), 400

        email = id_info['email']
        users = load_data(USERS_FILE)

        if email not in users:
            users[email] = {
                'senha': None,
                'bloqueado': False
            }
            save_data(users, USERS_FILE)

        session['email'] = email
        session['logged_in'] = True
        session['last_activity'] = datetime.now().timestamp()

        return redirect(url_for('main_page'))

    except Exception as e:
        print(f"Erro no callback do Google: {str(e)}")
        return jsonify({'erro': 'Falha na autenticação com o Google', 'detalhes': str(e)}), 400


@app.route('/main', methods=['GET'])
def main_page():
    if 'logged_in' in session and session['logged_in']:
        return "Bem-vindo à página principal!"
    return redirect(url_for('login'))


@app.before_request
def session_management():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

    if 'logged_in' in session and session['logged_in']:
        now = datetime.now().timestamp()
        last_activity = session.get('last_activity', now)
        if now - last_activity > 1800:  
            session.clear()
            return redirect(url_for('login'))
        session['last_activity'] = now


init_storage()

if __name__ == '__main__':
    app.run(port=5000, debug=True)
