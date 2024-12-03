from flask import Flask, request, jsonify, redirect, url_for, session, render_template
from flask_cors import CORS
import json
import hashlib
import time
import os
from datetime import datetime, timedelta
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'
CORS(app)

ARQUIVO_USUARIOS = 'usuarios.json'
ARQUIVO_CODIGOS = 'codigos_ativos.json'
ARQUIVO_BLOQUEIOS_IP = 'bloqueios_ip.json'
MAX_TENTATIVAS = 5

TEMPOS_BLOQUEIO = {
    1: 2,
    2: 5,
    3: 8,
    4: 9,
    5: 10
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
    arquivos = {
        ARQUIVO_USUARIOS: {
            "a@b.c": {
                "senha": hashlib.sha256("senha".encode()).hexdigest(),
                "bloqueado": False
            }
        },
        ARQUIVO_CODIGOS: {},
        ARQUIVO_BLOQUEIOS_IP: {}
    }

    for nome_arquivo, dados_padrao in arquivos.items():
        if not os.path.exists(nome_arquivo):
            with open(nome_arquivo, 'w') as f:
                json.dump(dados_padrao, f)


def carregar_dados(nome_arquivo):
    with open(nome_arquivo, 'r') as f:
        return json.load(f)


def salvar_dados(dados, nome_arquivo):
    with open(nome_arquivo, 'w') as f:
        json.dump(dados, f)


def obter_dados_ip(ip):
    bloqueios_ip = carregar_dados(ARQUIVO_BLOQUEIOS_IP)
    if ip not in bloqueios_ip:
        bloqueios_ip[ip] = {
            'tentativas': 0,
            'nivel_bloqueio': 0,
            'bloqueado_ate': 0,
            'ultimo_bloqueio': 0
        }
        salvar_dados(bloqueios_ip, ARQUIVO_BLOQUEIOS_IP)
    return bloqueios_ip[ip]


def is_ip_bloqueado(ip):
    dados_ip = obter_dados_ip(ip)
    current_time = time.time()
    if dados_ip['bloqueado_ate'] > current_time:
        return True, int(dados_ip['bloqueado_ate'] - current_time)
    return False, 0


def bloquear_ip(ip):
    bloqueios_ip = carregar_dados(ARQUIVO_BLOQUEIOS_IP)
    dados_ip = bloqueios_ip.get(ip, {
        'tentativas': 0,
        'nivel_bloqueio': 0,
        'bloqueado_ate': 0
    })

    current_time = time.time()

    if current_time <= dados_ip['bloqueado_ate']:
        nivel_bloqueio = min(dados_ip['nivel_bloqueio'] + 1, 5)

    elif dados_ip['nivel_bloqueio'] > 0:
        nivel_bloqueio = min(dados_ip['nivel_bloqueio'] + 1, 5)

    else:
        nivel_bloqueio = 1

    duracao_bloqueio = TEMPOS_BLOQUEIO[nivel_bloqueio]

    bloqueios_ip[ip] = {
        'tentativas': 0,
        'nivel_bloqueio': nivel_bloqueio,
        'bloqueado_ate': current_time + duracao_bloqueio
    }

    salvar_dados(bloqueios_ip, ARQUIVO_BLOQUEIOS_IP)
    return duracao_bloqueio


def incrementar_tentativas(ip):
    bloqueios_ip = carregar_dados(ARQUIVO_BLOQUEIOS_IP)
    dados_ip = obter_dados_ip(ip)
    dados_ip['tentativas'] += 1
    bloqueios_ip[ip] = dados_ip
    salvar_dados(bloqueios_ip, ARQUIVO_BLOQUEIOS_IP)

    if dados_ip['tentativas'] >= MAX_TENTATIVAS:
        return bloquear_ip(ip)
    return None


def resetar_tentativas(ip):
    bloqueios_ip = carregar_dados(ARQUIVO_BLOQUEIOS_IP)
    if ip in bloqueios_ip:
        bloqueios_ip[ip] = {
            'tentativas': 0,
            'nivel_bloqueio': 0,
            'bloqueado_ate': 0
        }
        salvar_dados(bloqueios_ip, ARQUIVO_BLOQUEIOS_IP)


def gerar_codigo_2fa():
    tempo_atual = datetime.now()
    hash_tempo = hashlib.sha256(str(tempo_atual.timestamp()).encode()).hexdigest()
    return str(int(hash_tempo[:8], 16) % 900000 + 100000)


@app.route('/api/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'logged_in' in session and session['logged_in']:
            return redirect(url_for('pagina_principal'))
        return render_template('login.html')

    try:
        dados = request.json
        email = dados.get('email')
        senha = dados.get('senha')
        ip = request.remote_addr

        if not email or not senha:
            return jsonify({'erro': 'Email e senha são obrigatórios'}), 400

        bloqueado, tempo_restante = is_ip_bloqueado(ip)
        if bloqueado:
            return jsonify({
                'erro': f'IP bloqueado por {tempo_restante} segundos',
                'tentativas_restantes': 0
            }), 403

        usuarios = carregar_dados(ARQUIVO_USUARIOS)
        usuario = usuarios.get(email)

        if not usuario or usuario['senha'] != hashlib.sha256(senha.encode()).hexdigest():

            duracao_bloqueio = incrementar_tentativas(ip)
            dados_ip = obter_dados_ip(ip)

            if duracao_bloqueio:
                return jsonify({
                    'erro': f'IP bloqueado por {duracao_bloqueio} segundos',
                    'tentativas_restantes': 0
                }), 403

            return jsonify({
                'erro': 'Credenciais inválidas',
                'tentativas_restantes': MAX_TENTATIVAS - dados_ip['tentativas']
            }), 401

        codigo = gerar_codigo_2fa()
        codigos = carregar_dados(ARQUIVO_CODIGOS)
        codigos[email] = {
            'codigo': codigo,
            'expira_em': time.time() + 120
        }
        salvar_dados(codigos, ARQUIVO_CODIGOS)

        resetar_tentativas(ip)

        print(f"Código 2FA para {email}: {codigo}")
        return jsonify({'mensagem': 'Código 2FA enviado'})

    except Exception as e:
        print(f"Erro no login: {str(e)}")
        return jsonify({'erro': 'Erro interno do servidor'}), 500


@app.route('/api/verificar-2fa', methods=['POST'])
def verificar_2fa():
    try:
        dados = request.json
        email = dados.get('email')
        codigo = dados.get('codigo')
        ip = request.remote_addr

        if not email or not codigo:
            return jsonify({'erro': 'Email e código são obrigatórios'}), 400

        bloqueado, tempo_restante = is_ip_bloqueado(ip)
        if bloqueado:
            return jsonify({
                'erro': f'IP bloqueado por {tempo_restante} segundos',
                'tentativas_restantes': 0
            }), 403

        codigos = carregar_dados(ARQUIVO_CODIGOS)
        dados_codigo = codigos.get(email)

        if not dados_codigo:
            return jsonify({'erro': 'Nenhum código ativo para este usuário'}), 400

        if time.time() > dados_codigo['expira_em']:
            del codigos[email]
            salvar_dados(codigos, ARQUIVO_CODIGOS)
            return jsonify({'erro': 'Código expirado'}), 400

        if codigo != dados_codigo['codigo']:

            duracao_bloqueio = incrementar_tentativas(ip)
            dados_ip = obter_dados_ip(ip)

            if duracao_bloqueio:
                return jsonify({
                    'erro': f'IP bloqueado por {duracao_bloqueio} segundos',
                    'tentativas_restantes': 0
                }), 403

            return jsonify({
                'erro': 'Código inválido',
                'tentativas_restantes': MAX_TENTATIVAS - dados_ip['tentativas']
            }), 401

        del codigos[email]
        salvar_dados(codigos, ARQUIVO_CODIGOS)
        resetar_tentativas(ip)

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

        google_request = google.auth.transport.requests.Request()

        id_info = id_token.verify_oauth2_token(
            flow.credentials.id_token,
            google_request,
            clock_skew_in_seconds=10
        )

        if 'email' not in id_info:
            return jsonify({'erro': 'Email não encontrado nas informações do Google'}), 400

        email = id_info['email']
        usuarios = carregar_dados(ARQUIVO_USUARIOS)

        if email not in usuarios:
            usuarios[email] = {
                'senha': None,
                'bloqueado': False
            }
            salvar_dados(usuarios, ARQUIVO_USUARIOS)

        session['email'] = email
        session['logged_in'] = True
        session['last_activity'] = datetime.now().timestamp()

        return redirect(url_for('pagina_principal'))

    except Exception as e:
        print(f"Erro no callback do Google: {str(e)}")
        return jsonify({'erro': 'Falha na autenticação com o Google', 'detalhes': str(e)}), 400


@app.route('/index', methods=['GET'])
def pagina_principal():
    if 'logged_in' in session and session['logged_in']:
        return render_template('index.html')
    return redirect(url_for('login'))


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.before_request
def gerenciar_sessao():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True

    if 'logged_in' in session and session['logged_in']:
        agora = datetime.now().timestamp()
        ultima_atividade = session.get('last_activity', agora)
        if agora - ultima_atividade > 1800:
            session.clear()
            return redirect(url_for('login'))
        session['last_activity'] = agora


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/')
def root():
    if 'logged_in' in session and session['logged_in']:
        return redirect(url_for('pagina_principal'))
    return redirect(url_for('login'))


init_storage()

if __name__ == '__main__':
    app.run(port=5000, debug=True)
