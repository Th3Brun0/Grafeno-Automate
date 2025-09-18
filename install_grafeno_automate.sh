#!/bin/bash

# Script de instalação automática do Grafeno Automate v2
# Sistema de gerenciamento de Mikrotiks com Ansible e interface web aprimorada.

set -e

echo "====================================================="
echo "    GRAFENO AUTOMATE v2 - INSTALAÇÃO AUTOMATIZADA"
echo "====================================================="

# --- Configuração de Cores ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Funções de Log ---
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[AVISO]${NC} $1"; }
error() { echo -e "${RED}[ERRO]${NC} $1"; exit 1; }
step() { echo -e "\n${BLUE}--- $1 ---${NC}"; }

# --- Verificação de Root ---
if [ "$EUID" -ne 0 ]; then
    error "Execute este script como root (ex: sudo ./install_grafeno_automate.sh)"
fi

# --- Variáveis de Configuração ---
APP_DIR="/opt/grafeno_automate"
APP_USER="grafeno"

# ==============================================================================
# 1. PREPARAÇÃO DO SISTEMA
# ==============================================================================
step "1. Preparando o Sistema Operacional"

log "Atualizando a lista de pacotes e o sistema..."
apt-get update && apt-get upgrade -y

log "Instalando dependências essenciais (Python, Nginx, Ansible)..."
apt-get install -y python3 python3-pip python3-venv nginx git curl openssl ansible

# --- Criação de Usuário e Diretório ---
if ! id "$APP_USER" &>/dev/null; then
    log "Criando usuário '$APP_USER' para a aplicação..."
    useradd -m -s /bin/bash "$APP_USER"
else
    log "Usuário '$APP_USER' já existe."
fi

log "Criando diretório da aplicação em $APP_DIR..."
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# ==============================================================================
# 2. GERAÇÃO DOS ARQUIVOS DA APLICAÇÃO
# ==============================================================================
step "2. Gerando Arquivos da Aplicação Flask"

# --- Geração de Segredos ---
log "Gerando chave secreta para o Flask..."
SECRET_KEY=$(openssl rand -hex 32)

log "Gerando senha forte para o usuário 'admin'..."
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)

# --- Ambiente Virtual e Dependências Python ---
log "Criando e ativando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

log "Criando arquivo requirements.txt..."
cat > requirements.txt << EOF
flask
flask-login
flask_sqlalchemy
gunicorn
bcrypt
EOF

log "Instalando dependências Python no ambiente virtual..."
pip install --upgrade pip
pip install -r requirements.txt
deactivate

# --- Estrutura de Diretórios ---
log "Criando estrutura de diretórios (templates, static, ansible)..."
mkdir -p templates static/css ansible/playbooks logs

# --- Arquivo Principal: app.py ---
log "Gerando o arquivo principal da aplicação (app.py)..."
cat > app.py << 'EOF'
import os
import logging
from datetime import datetime
import subprocess
import json
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuração da Aplicação ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grafeno_automate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ANSIBLE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ansible')

logging.basicConfig(filename='logs/app.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "warning"

# --- Models do Banco de Dados ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(40), nullable=False, unique=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'))

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    mikrotiks = db.relationship('Mikrotik', backref='grupo', lazy=True)

class Comando(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    command = db.Column(db.Text, nullable=False)

class LogExecucao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mikrotik_id = db.Column(db.Integer, db.ForeignKey('mikrotik.id'))
    comando_id = db.Column(db.Integer, db.ForeignKey('comando.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False) # success, failed, unreachable
    output = db.Column(db.Text)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    mikrotik = db.relationship('Mikrotik')
    comando = db.relationship('Comando')
    user = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Rotas Principais (Abas) ---
@app.route('/')
@login_required
def dashboard():
    stats = {
        'mikrotiks': Mikrotik.query.count(),
        'grupos': Grupo.query.count(),
        'comandos': Comando.query.count(),
        'logs': LogExecucao.query.count()
    }
    recent_logs = LogExecucao.query.order_by(LogExecucao.executed_at.desc()).limit(5).all()
    return render_template('dashboard.html', stats=stats, logs=recent_logs, all_mikrotiks=Mikrotik.query.all(), all_comandos=Comando.query.all())

@app.route('/mikrotiks')
@login_required
def gerenciar_mikrotiks():
    mikrotiks = Mikrotik.query.order_by(Mikrotik.name).all()
    grupos = Grupo.query.all()
    return render_template('gerenciar_mikrotiks.html', mikrotiks=mikrotiks, grupos=grupos)

@app.route('/comandos')
@login_required
def gerenciar_comandos():
    comandos = Comando.query.order_by(Comando.name).all()
    return render_template('gerenciar_comandos.html', comandos=comandos)

@app.route('/grupos')
@login_required
def gerenciar_grupos():
    grupos = Grupo.query.order_by(Grupo.name).all()
    return render_template('gerenciar_grupos.html', grupos=grupos)

@app.route('/logs')
@login_required
def ver_logs():
    page = request.args.get('page', 1, type=int)
    logs = LogExecucao.query.order_by(LogExecucao.executed_at.desc()).paginate(page=page, per_page=20)
    return render_template('ver_logs.html', logs=logs)

# --- Rotas de Ações (Adicionar, Deletar) ---
@app.route('/mikrotik/add', methods=['POST'])
@login_required
def add_mikrotik():
    grupo_id = request.form.get('grupo_id')
    new_mikrotik = Mikrotik(
        name=request.form['name'],
        ip=request.form['ip'],
        username=request.form['username'],
        password=request.form['password'],
        grupo_id=int(grupo_id) if grupo_id else None
    )
    db.session.add(new_mikrotik)
    db.session.commit()
    flash(f'Mikrotik "{new_mikrotik.name}" adicionado com sucesso!', 'success')
    return redirect(url_for('gerenciar_mikrotiks'))

@app.route('/mikrotik/<int:id>/delete', methods=['POST'])
@login_required
def delete_mikrotik(id):
    mikrotik = Mikrotik.query.get_or_404(id)
    LogExecucao.query.filter_by(mikrotik_id=id).update({LogExecucao.mikrotik_id: None})
    db.session.delete(mikrotik)
    db.session.commit()
    flash(f'Mikrotik "{mikrotik.name}" removido.', 'success')
    return redirect(url_for('gerenciar_mikrotiks'))

@app.route('/comando/add', methods=['POST'])
@login_required
def add_comando():
    new_cmd = Comando(name=request.form['name'], command=request.form['command'])
    db.session.add(new_cmd)
    db.session.commit()
    flash(f'Comando "{new_cmd.name}" adicionado!', 'success')
    return redirect(url_for('gerenciar_comandos'))

@app.route('/comando/<int:id>/delete', methods=['POST'])
@login_required
def delete_comando(id):
    cmd = Comando.query.get_or_404(id)
    LogExecucao.query.filter_by(comando_id=id).update({LogExecucao.comando_id: None})
    db.session.delete(cmd)
    db.session.commit()
    flash(f'Comando "{cmd.name}" removido.', 'success')
    return redirect(url_for('gerenciar_comandos'))

@app.route('/grupo/add', methods=['POST'])
@login_required
def add_grupo():
    new_group = Grupo(name=request.form['name'])
    db.session.add(new_group)
    db.session.commit()
    flash(f'Grupo "{new_group.name}" criado!', 'success')
    return redirect(url_for('gerenciar_grupos'))

@app.route('/grupo/<int:id>/delete', methods=['POST'])
@login_required
def delete_grupo(id):
    group = Grupo.query.get_or_404(id)
    Mikrotik.query.filter_by(grupo_id=id).update({Mikrotik.grupo_id: None})
    db.session.delete(group)
    db.session.commit()
    flash(f'Grupo "{group.name}" removido.', 'success')
    return redirect(url_for('gerenciar_grupos'))

# --- Rota de Execução com Ansible ---
@app.route('/executar_ansible', methods=['POST'])
@login_required
def executar_ansible():
    mikrotik_id = request.form.get('mikrotik_id')
    comando_id = request.form.get('comando_id')

    mikrotik = Mikrotik.query.get_or_404(mikrotik_id)
    comando = Comando.query.get_or_404(comando_id)

    inventory_content = f"""
[mikrotik]
{mikrotik.ip}

[mikrotik:vars]
ansible_user={mikrotik.username}
ansible_password={mikrotik.password}
ansible_network_os=routeros
ansible_connection=network_cli
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
"""
    inventory_path = os.path.join(app.config['ANSIBLE_DIR'], f'inventory_{mikrotik.id}.ini')
    with open(inventory_path, 'w') as f:
        f.write(inventory_content)

    playbook_path = os.path.join(app.config['ANSIBLE_DIR'], 'playbooks', 'run_command.yml')
    cmd_to_run = [
        'ansible-playbook',
        '-i', inventory_path,
        playbook_path,
        '--extra-vars', f"target_host={mikrotik.ip} routeros_command='{comando.command}'"
    ]
    
    status = "failed"
    log_output = ""

    try:
        result = subprocess.run(cmd_to_run, capture_output=True, text=True, timeout=60)
        
        recap_line = [line for line in result.stdout.splitlines() if "PLAY RECAP" in line]
        if recap_line:
            if f"unreachable=1" in recap_line[0]: status = "unreachable"
            elif f"failed=1" in recap_line[0]: status = "failed"
            else: status = "success"
        
        log_output = result.stdout + "\n" + result.stderr
        flash(f'Comando "{comando.name}" em "{mikrotik.name}". Status: {status.upper()}', 'success' if status == 'success' else 'danger')

    except subprocess.TimeoutExpired as e:
        status = "failed"
        log_output = "Timeout: A execução demorou mais de 60 segundos."
        flash(f'Timeout ao executar comando em "{mikrotik.name}".', 'danger')
    except Exception as e:
        status = "failed"
        log_output = str(e)
        flash(f'Erro inesperado ao executar playbook para "{mikrotik.name}".', 'danger')

    finally:
        if os.path.exists(inventory_path):
            os.remove(inventory_path)

    new_log = LogExecucao(
        mikrotik_id=mikrotik.id,
        comando_id=comando.id,
        user_id=current_user.id,
        status=status,
        output=log_output
    )
    db.session.add(new_log)
    db.session.commit()

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

# --- Templates HTML ---
log "Gerando templates HTML (base, login, dashboard e abas)..."

# templates/base.html
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Grafeno Automate{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css' ) }}">
</head>
<body>
    <div class="d-flex">
        {% if current_user.is_authenticated %}
        <nav class="sidebar">
            <h1 class="sidebar-header">GRAFENO</h1>
            <ul class="nav flex-column">
                <li class="nav-item"><a class="nav-link {% if request.path == url_for('dashboard') %}active{% endif %}" href="{{ url_for('dashboard') }}"><i class="bi bi-grid-fill me-2"></i> Dashboard</a></li>
                <li class="nav-item"><a class="nav-link {% if 'mikrotik' in request.path %}active{% endif %}" href="{{ url_for('gerenciar_mikrotiks') }}"><i class="bi bi-router-fill me-2"></i> Mikrotiks</a></li>
                <li class="nav-item"><a class="nav-link {% if 'comando' in request.path %}active{% endif %}" href="{{ url_for('gerenciar_comandos') }}"><i class="bi bi-terminal-fill me-2"></i> Comandos</a></li>
                <li class="nav-item"><a class="nav-link {% if 'grupo' in request.path %}active{% endif %}" href="{{ url_for('gerenciar_grupos') }}"><i class="bi bi-collection-fill me-2"></i> Grupos</a></li>
                <li class="nav-item"><a class="nav-link {% if 'log' in request.path %}active{% endif %}" href="{{ url_for('ver_logs') }}"><i class="bi bi-file-earmark-text-fill me-2"></i> Logs</a></li>
            </ul>
            <div class="sidebar-footer">
                <span><i class="bi bi-person-circle me-2"></i>{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}" class="btn btn-sm btn-outline-light"><i class="bi bi-box-arrow-right"></i> Sair</a>
            </div>
        </nav>
        {% endif %}

        <main class="main-content">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    <div class="flash-messages">
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>
                    {% endfor %}
                    </div>
                {% endif %}
            {% endwith %}
            {% block content %}{% endblock %}
        </main>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# templates/login.html
cat > templates/login.html << 'EOF'
{% extends "base.html" %}
{% block title %}Login - Grafeno Automate{% endblock %}
{% block content %}
<div class="container">
    <div class="row justify-content-center align-items-center vh-100">
        <div class="col-md-6 col-lg-4">
            <div class="card shadow-lg">
                <div class="card-body p-5">
                    <h2 class="text-center fw-bold mb-4">GRAFENO AUTOMATE</h2>
                    {% with messages = get_flashed_messages(with_categories=true ) %}
                        {% if messages %}
                            {% for category, message in messages %}
                                <div class="alert alert-{{ category }}">{{ message }}</div>
                            {% endfor %}
                        {% endif %}
                    {% endwith %}
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Usuário</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-4">
                            <label for="password" class="form-label">Senha</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Entrar</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# templates/dashboard.html
cat > templates/dashboard.html << 'EOF'
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<div class="container-fluid">
    <h3 class="mb-4">Dashboard</h3>
    <div class="row">
        <div class="col-xl-3 col-md-6 mb-4"><div class="card border-left-primary shadow h-100 py-2"><div class="card-body"><div class="row no-gutters align-items-center"><div class="col mr-2"><div class="text-xs fw-bold text-primary text-uppercase mb-1">Mikrotiks</div><div class="h5 mb-0 fw-bold text-gray-800">{{ stats.mikrotiks }}</div></div><div class="col-auto"><i class="bi bi-router-fill fs-2 text-gray-300"></i></div></div></div></div></div>
        <div class="col-xl-3 col-md-6 mb-4"><div class="card border-left-success shadow h-100 py-2"><div class="card-body"><div class="row no-gutters align-items-center"><div class="col mr-2"><div class="text-xs fw-bold text-success text-uppercase mb-1">Grupos</div><div class="h5 mb-0 fw-bold text-gray-800">{{ stats.grupos }}</div></div><div class="col-auto"><i class="bi bi-collection-fill fs-2 text-gray-300"></i></div></div></div></div></div>
        <div class="col-xl-3 col-md-6 mb-4"><div class="card border-left-info shadow h-100 py-2"><div class="card-body"><div class="row no-gutters align-items-center"><div class="col mr-2"><div class="text-xs fw-bold text-info text-uppercase mb-1">Comandos</div><div class="h5 mb-0 fw-bold text-gray-800">{{ stats.comandos }}</div></div><div class="col-auto"><i class="bi bi-terminal-fill fs-2 text-gray-300"></i></div></div></div></div></div>
        <div class="col-xl-3 col-md-6 mb-4"><div class="card border-left-warning shadow h-100 py-2"><div class="card-body"><div class="row no-gutters align-items-center"><div class="col mr-2"><div class="text-xs fw-bold text-warning text-uppercase mb-1">Execuções</div><div class="h5 mb-0 fw-bold text-gray-800">{{ stats.logs }}</div></div><div class="col-auto"><i class="bi bi-file-earmark-text-fill fs-2 text-gray-300"></i></div></div></div></div></div>
    </div>
    <div class="card shadow mb-4">
        <div class="card-header py-3"><h6 class="m-0 fw-bold text-primary">Execução Rápida de Comando</h6></div>
        <div class="card-body">
            <form action="{{ url_for('executar_ansible') }}" method="POST">
                <div class="row align-items-end">
                    <div class="col-md-5 mb-3"><label for="mikrotik_id" class="form-label">Selecione o Mikrotik</label><select name="mikrotik_id" class="form-select" required><option value="" disabled selected>Escolha um Mikrotik...</option>{% for m in all_mikrotiks %}<option value="{{ m.id }}">{{ m.name }} ({{ m.ip }})</option>{% endfor %}</select></div>
                    <div class="col-md-5 mb-3"><label for="comando_id" class="form-label">Selecione o Comando</label><select name="comando_id" class="form-select" required><option value="" disabled selected>Escolha um Comando...</option>{% for c in all_comandos %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}</select></div>
                    <div class="col-md-2 mb-3"><button type="submit" class="btn btn-primary w-100">Executar</button></div>
                </div>
            </form>
        </div>
    </div>
    <div class="card shadow mb-4">
        <div class="card-header py-3"><h6 class="m-0 fw-bold text-primary">Logs de Execução Recentes</h6></div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-bordered" width="100%" cellspacing="0">
                    <thead><tr><th>Data</th><th>Mikrotik</th><th>Comando</th><th>Status</th><th>Usuário</th></tr></thead>
                    <tbody>
                        {% for log in logs %}
                        <tr>
                            <td>{{ log.executed_at.strftime('%d/%m/%Y %H:%M') }}</td>
                            <td>{{ log.mikrotik.name if log.mikrotik else 'N/A' }}</td>
                            <td>{{ log.comando.name if log.comando else 'N/A' }}</td>
                            <td><span class="badge bg-{% if log.status == 'success' %}success{% elif log.status == 'unreachable' %}warning text-dark{% else %}danger{% endif %}">{{ log.status }}</span></td>
                            <td>{{ log.user.username if log.user else 'N/A' }}</td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="text-center">Nenhuma execução registrada.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# templates/gerenciar_mikrotiks.html
cat > templates/gerenciar_mikrotiks.html << 'EOF'
{% extends "base.html" %}
{% block title %}Gerenciar Mikrotiks{% endblock %}
{% block content %}
<div class="container-fluid">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3>Gerenciar Mikrotiks</h3>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addMikrotikModal"><i class="bi bi-plus-circle me-2"></i>Adicionar Mikrotik</button>
    </div>
    <div class="card shadow">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>Nome</th><th>IP</th><th>Usuário</th><th>Grupo</th><th>Ações</th></tr></thead>
                    <tbody>
                        {% for m in mikrotiks %}
                        <tr>
                            <td>{{ m.name }}</td>
                            <td>{{ m.ip }}</td>
                            <td>{{ m.username }}</td>
                            <td>{{ m.grupo.name if m.grupo else 'Nenhum' }}</td>
                            <td>
                                <form action="{{ url_for('delete_mikrotik', id=m.id) }}" method="POST" onsubmit="return confirm('Tem certeza que deseja remover este Mikrotik?');" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                                </form>
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="5" class="text-center">Nenhum Mikrotik cadastrado.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<!-- Modal Adicionar Mikrotik -->
<div class="modal fade" id="addMikrotikModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header"><h5 class="modal-title">Adicionar Novo Mikrotik</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
      <div class="modal-body">
        <form action="{{ url_for('add_mikrotik') }}" method="POST">
            <div class="mb-3"><label class="form-label">Nome</label><input type="text" name="name" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Endereço IP</label><input type="text" name="ip" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Usuário</label><input type="text" name="username" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Senha</label><input type="password" name="password" class="form-control" required></div>
            <div class="mb-3"><label class="form-label">Grupo</label><select name="grupo_id" class="form-select"><option value="">Nenhum</option>{% for g in grupos %}<option value="{{ g.id }}">{{ g.name }}</option>{% endfor %}</select></div>
            <button type="submit" class="btn btn-primary">Salvar</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
EOF

# templates/gerenciar_comandos.html
cat > templates/gerenciar_comandos.html << 'EOF'
{% extends "base.html" %}
{% block title %}Gerenciar Comandos{% endblock %}
{% block content %}
<div class="container-fluid">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3>Gerenciar Comandos</h3>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addComandoModal"><i class="bi bi-plus-circle me-2"></i>Adicionar Comando</button>
    </div>
    <div class="card shadow">
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>Nome</th><th>Comando RouterOS</th><th>Ações</th></tr></thead>
                    <tbody>
                        {% for c in comandos %}
                        <tr>
                            <td>{{ c.name }}</td>
                            <td><code>{{ c.command }}</code></td>
                            <td>
                                <form action="{{ url_for('delete_comando', id=c.id) }}" method="POST" onsubmit="return confirm('Tem certeza?');" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                                </form>
                            </td>
                        </tr>
                        {% else %}
                        <tr><td colspan="3" class="text-center">Nenhum comando cadastrado.</td></tr>
                        {% endfor %}
                    </tbody>
