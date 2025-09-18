#!/bin/bash
# install_ansitrix.sh - Script de instalação automática do Ansitrix

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para log colorido
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar se é Ubuntu
if ! grep -q "Ubuntu" /etc/os-release; then
    error "Este script foi desenvolvido para Ubuntu. Abortando."
    exit 1
fi

log "=== INSTALAÇÃO DO ANSITRIX ==="
log "Ferramenta de gerenciamento centralizado de Mikrotiks via Ansible"

# Atualizar sistema
log "Atualizando sistema..."
sudo apt update && sudo apt upgrade -y

# Instalar dependências
log "Instalando dependências do sistema..."
sudo apt install -y python3 python3-pip python3-venv git sshpass curl nginx

# Criar diretório da aplicação
log "Criando estrutura de diretórios..."
sudo mkdir -p /opt/ansitrix
sudo chown $USER:$USER /opt/ansitrix
cd /opt/ansitrix

# Criar ambiente virtual
log "Criando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

# Instalar bibliotecas Python
log "Instalando bibliotecas Python..."
pip install --upgrade pip
pip install flask flask-login flask-wtf flask-sqlalchemy bcrypt cryptography ansible ansible-runner paramiko netmiko

# Criar estrutura de pastas
mkdir -p {templates,static/css,static/js,data}

log "Criando arquivos da aplicação..."

# Criar config.py
cat > config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ansitrix_secret_key_change_in_production_2024'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ansitrix.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
EOF

# Criar models.py
cat > models.py << 'EOF'
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), unique=True, nullable=False)
    descricao = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mikrotiks = db.relationship('Mikrotik', backref='grupo', lazy=True, cascade='all, delete-orphan')

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    ssh_port = db.Column(db.Integer, default=22)
    ssh_user = db.Column(db.String(50), default='admin')
    ssh_password = db.Column(db.String(255))
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'), nullable=False)
    status = db.Column(db.String(20), default='ativo')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Comando(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), nullable=False)
    comando = db.Column(db.Text, nullable=False)
    descricao = db.Column(db.Text)
    categoria = db.Column(db.String(50), default='geral')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LogExecucao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comando_id = db.Column(db.Integer, db.ForeignKey('comando.id'), nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'))
    resultado = db.Column(db.Text)
    status = db.Column(db.String(20))
    executado_em = db.Column(db.DateTime, default=datetime.utcnow)
    
    usuario = db.relationship('User', backref='execucoes')
    comando = db.relationship('Comando')
    grupo = db.relationship('Grupo')
EOF

# Criar ansible_runner.py
cat > ansible_runner.py << 'EOF'
import subprocess
import tempfile
import os
import json
from models import Mikrotik

def create_inventory(mikrotiks):
    """Cria inventário Ansible temporário"""
    inventory_content = "[mikrotiks]\n"
    for mk in mikrotiks:
        inventory_content += f"{mk.ip} ansible_ssh_port={mk.ssh_port} ansible_ssh_user={mk.ssh_user} ansible_ssh_pass={mk.ssh_password}\n"
    
    inventory_content += "\n[mikrotiks:vars]\n"
    inventory_content += "ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n"
    inventory_content += "ansible_connection=ssh\n"
    
    return inventory_content

def run_ansible_command(mikrotiks, command):
    """Executa comando via Ansible"""
    if not mikrotiks:
        return {"error": "Nenhum Mikrotik selecionado"}
    
    with tempfile.TemporaryDirectory() as tmpdir:
        inventory_path = os.path.join(tmpdir, 'inventory.ini')
        
        with open(inventory_path, 'w') as f:
            f.write(create_inventory(mikrotiks))
        
        cmd = [
            'ansible', 'mikrotiks', 
            '-i', inventory_path,
            '-m', 'raw',
            '-a', command,
            '--timeout=30'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {"error": "Timeout na execução do comando"}
        except Exception as e:
            return {"error": f"Erro na execução: {str(e)}"}

def test_connection(mikrotik):
    """Testa conectividade SSH com um Mikrotik"""
    with tempfile.TemporaryDirectory() as tmpdir:
        inventory_path = os.path.join(tmpdir, 'inventory.ini')
        
        with open(inventory_path, 'w') as f:
            f.write(create_inventory([mikrotik]))
        
        cmd = [
            'ansible', 'mikrotiks', 
            '-i', inventory_path,
            '-m', 'raw',
            '-a', '/system identity print',
            '--timeout=10'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except:
            return False
EOF

# Criar app.py
cat > app.py << 'EOF'
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Mikrotik, Grupo, Comando, LogExecucao
from ansible_runner import run_ansible_command, test_connection
from config import Config
from datetime import datetime
import json

app = Flask(__name__)
app.config.from_object(Config)

# Inicializar extensões
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.login_message_category = 'warning'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Criar tabelas e dados iniciais
with app.app_context():
    db.create_all()
    
    # Criar usuário admin padrão
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', role='admin')
        admin.set_password('ChangeMe123!')
        db.session.add(admin)
        db.session.commit()
        print("Usuário admin criado com senha: ChangeMe123!")
    
    # Criar grupo padrão
    grupo_default = Grupo.query.filter_by(nome='Default').first()
    if not grupo_default:
        grupo_default = Grupo(nome='Default', descricao='Grupo padrão')
        db.session.add(grupo_default)
        db.session.commit()
    
    # Criar comandos padrão
    comandos_default = [
        {'nome': 'Reboot', 'comando': '/system reboot', 'descricao': 'Reiniciar o equipamento', 'categoria': 'sistema'},
        {'nome': 'Identidade', 'comando': '/system identity print', 'descricao': 'Mostrar identidade do sistema', 'categoria': 'info'},
        {'nome': 'Versão', 'comando': '/system resource print', 'descricao': 'Informações do sistema', 'categoria': 'info'},
        {'nome': 'Interfaces', 'comando': '/interface print', 'descricao': 'Listar interfaces', 'categoria': 'rede'},
        {'nome': 'Export Config', 'comando': '/export', 'descricao': 'Exportar configuração completa', 'categoria': 'backup'},
        {'nome': 'IPs', 'comando': '/ip address print', 'descricao': 'Mostrar endereços IP', 'categoria': 'rede'},
        {'nome': 'Routes', 'comando': '/ip route print', 'descricao': 'Mostrar tabela de rotas', 'categoria': 'rede'},
        {'nome': 'DHCP Leases', 'comando': '/ip dhcp-server lease print', 'descricao': 'Mostrar concessões DHCP', 'categoria': 'dhcp'},
    ]
    
    for cmd_data in comandos_default:
        cmd = Comando.query.filter_by(nome=cmd_data['nome']).first()
        if not cmd:
            cmd = Comando(**cmd_data)
            db.session.add(cmd)
    
    db.session.commit()

@app.route('/')
@login_required
def dashboard():
    total_mikrotiks = Mikrotik.query.count()
    total_grupos = Grupo.query.count()
    total_comandos = Comando.query.count()
    execucoes_recentes = LogExecucao.query.order_by(LogExecucao.executado_em.desc()).limit(10).all()
    
    return render_template('dashboard.html', 
                         total_mikrotiks=total_mikrotiks,
                         total_grupos=total_grupos,
                         total_comandos=total_comandos,
                         execucoes_recentes=execucoes_recentes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso', 'success')
    return redirect(url_for('login'))

@app.route('/grupos')
@login_required
def grupos():
    grupos = Grupo.query.all()
    return render_template('grupos.html', grupos=grupos)

@app.route('/grupos/add', methods=['POST'])
@login_required
def add_grupo():
    nome = request.form['nome'].strip()
    descricao = request.form.get('descricao', '').strip()
    
    if Grupo.query.filter_by(nome=nome).first():
        flash('Grupo com este nome já existe', 'danger')
    else:
        grupo = Grupo(nome=nome, descricao=descricao)
        db.session.add(grupo)
        db.session.commit()
        flash('Grupo criado com sucesso', 'success')
    
    return redirect(url_for('grupos'))

@app.route('/mikrotiks')
@login_required
def mikrotiks():
    grupos = Grupo.query.all()
    mikrotiks = Mikrotik.query.all()
    return render_template('mikrotiks.html', mikrotiks=mikrotiks, grupos=grupos)

@app.route('/mikrotiks/add', methods=['POST'])
@login_required
def add_mikrotik():
    nome = request.form['nome'].strip()
    ip = request.form['ip'].strip()
    ssh_port = int(request.form.get('ssh_port', 22))
    ssh_user = request.form.get('ssh_user', 'admin').strip()
    ssh_password = request.form['ssh_password']
    grupo_id = int(request.form['grupo_id'])
    
    mikrotik = Mikrotik(
        nome=nome, 
        ip=ip, 
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        ssh_password=ssh_password,
        grupo_id=grupo_id
    )
    
    db.session.add(mikrotik)
    db.session.commit()
    flash('Mikrotik adicionado com sucesso', 'success')
    
    return redirect(url_for('mikrotiks'))

@app.route('/mikrotiks/test/<int:id>')
@login_required
def test_mikrotik(id):
    mikrotik = Mikrotik.query.get_or_404(id)
    success = test_connection(mikrotik)
    
    if success:
        flash(f'Conexão com {mikrotik.nome} bem-sucedida', 'success')
    else:
        flash(f'Falha na conexão com {mikrotik.nome}', 'danger')
    
    return redirect(url_for('mikrotiks'))

@app.route('/comandos')
@login_required
def comandos():
    comandos = Comando.query.all()
    return render_template('comandos.html', comandos=comandos)

@app.route('/comandos/add', methods=['POST'])
@login_required
def add_comando():
    nome = request.form['nome'].strip()
    comando = request.form['comando'].strip()
    descricao = request.form.get('descricao', '').strip()
    categoria = request.form.get('categoria', 'geral').strip()
    
    cmd = Comando(nome=nome, comando=comando, descricao=descricao, categoria=categoria)
    db.session.add(cmd)
    db.session.commit()
    flash('Comando adicionado com sucesso', 'success')
    
    return redirect(url_for('comandos'))

@app.route('/executar')
@login_required
def executar():
    grupos = Grupo.query.all()
    comandos = Comando.query.all()
    return render_template('executar.html', grupos=grupos, comandos=comandos)

@app.route('/api/executar', methods=['POST'])
@login_required
def api_executar():
    data = request.json
    grupo_id = data.get('grupo_id')
    comando_id = data.get('comando_id')
    
    grupo = Grupo.query.get(grupo_id)
    comando = Comando.query.get(comando_id)
    
    if not grupo or not comando:
        return jsonify({'error': 'Grupo ou comando inválido'}), 400
    
    mikrotiks = grupo.mikrotiks
    if not mikrotiks:
        return jsonify({'error': 'Nenhum Mikrotik no grupo selecionado'}), 400
    
    # Executar comando
    resultado = run_ansible_command(mikrotiks, comando.comando)
    
    # Salvar log
    log = LogExecucao(
        usuario_id=current_user.id,
        comando_id=comando.id,
        grupo_id=grupo.id,
        resultado=json.dumps(resultado),
        status='sucesso' if resultado.get('returncode') == 0 else 'erro'
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify(resultado)

@app.route('/usuarios')
@login_required
def usuarios():
    if not current_user.is_admin():
        flash('Acesso negado. Apenas administradores podem gerenciar usuários.', 'danger')
        return redirect(url_for('dashboard'))
    
    usuarios = User.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/usuarios/add', methods=['POST'])
@login_required
def add_usuario():
    if not current_user.is_admin():
        return jsonify({'error': 'Acesso negado'}), 403
    
    username = request.form['username'].strip()
    password = request.form['password']
    role = request.form['role']
    
    if User.query.filter_by(username=username).first():
        flash('Usuário já existe', 'danger')
    else:
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Usuário criado com sucesso', 'success')
    
    return redirect(url_for('usuarios'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

# Criar templates base
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Ansitrix{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/style.css') }}" rel="stylesheet">
</head>
<body>
    {% if current_user.is_authenticated %}
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand d-flex align-items-center" href="{{ url_for('dashboard') }}">
                <i class="bi bi-router me-2"></i>
                <strong>Ansitrix</strong>
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="bi bi-speedometer2 me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('grupos') }}">
                            <i class="bi bi-collection me-1"></i>Grupos
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('mikrotiks') }}">
                            <i class="bi bi-router me-1"></i>Mikrotiks
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('comandos') }}">
                            <i class="bi bi-terminal me-1"></i>Comandos
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('executar') }}">
                            <i class="bi bi-play-circle me-1"></i>Executar
                        </a>
                    </li>
                    {% if current_user.is_admin() %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('usuarios') }}">
                            <i class="bi bi-people me-1"></i>Usuários
                        </a>
                    </li>
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="bi bi-person-circle me-1"></i>{{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="toggleTheme()">
                                <i class="bi bi-moon me-1"></i>Alternar Tema
                            </a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}">
                                <i class="bi bi-box-arrow-right me-1"></i>Sair
                            </a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    {% endif %}

    <div class="container-fluid mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            html.setAttribute('data-bs-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        }
        
        // Carregar tema salvo
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
    </script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

# Criar template de login
cat > templates/login.html << 'EOF'
{% extends "base.html" %}

{% block title %}Login - Ansitrix{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-4">
        <div class="card shadow">
            <div class="card-body">
                <div class="text-center mb-4">
                    <i class="bi bi-router" style="font-size: 3rem; color: var(--bs-primary);"></i>
                    <h3 class="card-title mt-2">Ansitrix</h3>
                    <p class="text-muted">Gerenciamento Centralizado de Mikrotiks</p>
                </div>
                
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Usuário</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">Senha</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    
                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="remember" name="remember">
                        <label class="form-check-label" for="remember">Lembrar-me</label>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="bi bi-box-arrow-in-right me-1"></i>Entrar
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Criar template dashboard
cat > templates/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block title %}Dashboard - Ansitrix{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="h3 mb-4">
            <i class="bi bi-speedometer2 me-2"></i>Dashboard
        </h1>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card text-white bg-primary">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h5 class="card-title">Mikrotiks</h5>
                        <h2>{{ total_mikrotiks }}</h2>
                    </div>
                    <i class="bi bi-router" style="font-size: 2rem;"></i>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-success">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h5 class="card-title">Grupos</h5>
                        <h2>{{ total_grupos }}</h2>
                    </div>
                    <i class="bi bi-collection" style="font-size: 2rem;"></i>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-info">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h5 class="card-title">Comandos</h5>
                        <h2>{{ total_comandos }}</h2>
                    </div>
                    <i class="bi bi-terminal" style="font-size: 2rem;"></i>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-warning">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h5 class="card-title">Online</h5>
                        <h2>-</h2>
                    </div>
                    <i class="bi bi-wifi" style="font-size: 2rem;"></i>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5 class="card-title mb-0">
                    <i class="bi bi-clock-history me-1"></i>Execuções Recentes
                </h5>
            </div>
            <div class="card-body">
                {% if execucoes_recentes %}
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Usuário</th>
                                <th>Comando</th>
                                <th>Grupo</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for exec in execucoes_recentes %}
                            <tr>
                                <td>{{ exec.executado_em.strftime('%d/%m/%Y %H:%M') }}</td>
                                <td>{{ exec.usuario.username }}</td>
                                <td>{{ exec.comando.nome }}</td>
                                <td>{{ exec.grupo.nome if exec.grupo else '-' }}</td>
                                <td>
                                    {% if exec.status == 'sucesso' %}
                                        <span class="badge bg-success">Sucesso</span>
                                    {% else %}
                                        <span class="badge bg-danger">Erro</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted">Nenhuma execução registrada ainda.</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Continuar criando os outros templates...
log "Criando templates restantes..."

# Criar mais alguns templates essenciais (grupos, mikrotiks, etc.)
cat > templates/grupos.html << 'EOF'
{% extends "base.html" %}

{% block title %}Grupos - Ansitrix{% endblock %}

{% block content %}
<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3">
                <i class="bi bi-collection me-2"></i>Grupos de Mikrotiks
            </h1>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addGrupoModal">
                <i class="bi bi-plus-circle me-1"></i>Novo Grupo
            </button>
        </div>
    </div>
</div>

<div class="row">
    {% for grupo in grupos %}
    <div class="col-md-6 col-lg-4 mb-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">{{ grupo.nome }}</h5>
                <p class="card-text">{{ grupo.descricao or 'Sem descrição' }}</p>
                <p class="text-muted small">
                    <i class="bi bi-router me-1"></i>{{ grupo.mikrotiks|length }} Mikrotik(s)
                </p>
                <p class="text-muted small">
                    Criado em: {{ grupo.created_at.strftime('%d/%m/%Y') }}
                </p>
            </div>
        </div>
    </div>
    {% endfor %}
</div>

<!-- Modal Adicionar Grupo -->
<div class="modal fade" id="addGrupoModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Novo Grupo</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_grupo') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="nome" class="form-label">Nome do Grupo</label>
                        <input type="text" class="form-control" id="nome" name="nome" required>
                    </div>
                    <div class="mb-3">
                        <label for="descricao" class="form-label">Descrição</label>
                        <textarea class="form-control" id="descricao" name="descricao" rows="3"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Criar CSS customizado
cat > static/css/style.css << 'EOF'
:root {
    --bs-primary: #0066cc;
    --bs-success: #28a745;
    --bs-info: #17a2b8;
    --bs-warning: #ffc107;
    --bs-danger: #dc3545;
}

[data-bs-theme="dark"] {
    --bs-body-bg: #1a1a1a;
    --bs-body-color: #e9ecef;
}

.navbar-brand {
    font-weight: 600;
}

.card {
    border: none;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    transition: box-shadow 0.15s ease-in-out;
}

.card:hover {
    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
}

.btn {
    border-radius: 0.375rem;
}

.table {
    border-radius: 0.375rem;
    overflow: hidden;
}

.alert {
    border-radius: 0.5rem;
}

pre {
    background-color: var(--bs-dark);
    color: var(--bs-light);
    padding: 1rem;
    border-radius: 0.375rem;
    max-height: 400px;
    overflow-y: auto;
}

[data-bs-theme="dark"] pre {
    background-color: #2d3748;
}

.loading {
    pointer-events: none;
    opacity: 0.6;
}
EOF

# Criar mais templates essenciais
log "Criando templates de mikrotiks e execução..."

cat > templates/mikrotiks.html << 'EOF'
{% extends "base.html" %}
{% block title %}Mikrotiks - Ansitrix{% endblock %}
{% block content %}
<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3"><i class="bi bi-router me-2"></i>Mikrotiks</h1>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addMikrotikModal">
                <i class="bi bi-plus-circle me-1"></i>Novo Mikrotik
            </button>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Nome</th>
                        <th>IP</th>
                        <th>Porta SSH</th>
                        <th>Grupo</th>
                        <th>Status</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {% for mk in mikrotiks %}
                    <tr>
                        <td><strong>{{ mk.nome }}</strong></td>
                        <td>{{ mk.ip }}</td>
                        <td>{{ mk.ssh_port }}</td>
                        <td><span class="badge bg-secondary">{{ mk.grupo.nome }}</span></td>
                        <td><span class="badge bg-success">{{ mk.status }}</span></td>
                        <td>
                            <a href="{{ url_for('test_mikrotik', id=mk.id) }}" class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-wifi"></i> Testar
                            </a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Modal -->
<div class="modal fade" id="addMikrotikModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Novo Mikrotik</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_mikrotik') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="nome" class="form-label">Nome</label>
                        <input type="text" class="form-control" id="nome" name="nome" required>
                    </div>
                    <div class="mb-3">
                        <label for="ip" class="form-label">IP</label>
                        <input type="text" class="form-control" id="ip" name="ip" required>
                    </div>
                    <div class="mb-3">
                        <label for="ssh_port" class="form-label">Porta SSH</label>
                        <input type="number" class="form-control" id="ssh_port" name="ssh_port" value="22">
                    </div>
                    <div class="mb-3">
                        <label for="ssh_user" class="form-label">Usuário SSH</label>
                        <input type="text" class="form-control" id="ssh_user" name="ssh_user" value="admin">
                    </div>
                    <div class="mb-3">
                        <label for="ssh_password" class="form-label">Senha SSH</label>
                        <input type="password" class="form-control" id="ssh_password" name="ssh_password" required>
                    </div>
                    <div class="mb-3">
                        <label for="grupo_id" class="form-label">Grupo</label>
                        <select class="form-select" id="grupo_id" name="grupo_id" required>
                            {% for grupo in grupos %}
                            <option value="{{ grupo.id }}">{{ grupo.nome }}</option>
                            {% endfor %}
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

cat > templates/comandos.html << 'EOF'
{% extends "base.html" %}
{% block title %}Comandos - Ansitrix{% endblock %}
{% block content %}
<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3"><i class="bi bi-terminal me-2"></i>Comandos</h1>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addComandoModal">
                <i class="bi bi-plus-circle me-1"></i>Novo Comando
            </button>
        </div>
    </div>
</div>

<div class="row">
    {% for cmd in comandos %}
    <div class="col-md-6 col-lg-4 mb-3">
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">{{ cmd.nome }}</h5>
                <p class="card-text">{{ cmd.descricao or 'Sem descrição' }}</p>
                <code class="small">{{ cmd.comando }}</code>
                <div class="mt-2">
                    <span class="badge bg-info">{{ cmd.categoria }}</span>
                </div>
            </div>
        </div>
    </div>
    {% endfor %}
</div>

<!-- Modal -->
<div class="modal fade" id="addComandoModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Novo Comando</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_comando') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="nome" class="form-label">Nome</label>
                        <input type="text" class="form-control" id="nome" name="nome" required>
                    </div>
                    <div class="mb-3">
                        <label for="comando" class="form-label">Comando</label>
                        <textarea class="form-control" id="comando" name="comando" rows="3" required></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="descricao" class="form-label">Descrição</label>
                        <textarea class="form-control" id="descricao" name="descricao" rows="2"></textarea>
                    </div>
                    <div class="mb-3">
                        <label for="categoria" class="form-label">Categoria</label>
                        <select class="form-select" id="categoria" name="categoria">
                            <option value="geral">Geral</option>
                            <option value="sistema">Sistema</option>
                            <option value="rede">Rede</option>
                            <option value="dhcp">DHCP</option>
                            <option value="backup">Backup</option>
                            <option value="info">Informação</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Salvar</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

cat > templates/executar.html << 'EOF'
{% extends "base.html" %}
{% block title %}Executar - Ansitrix{% endblock %}
{% block content %}
<div class="row">
    <div class="col-12">
        <h1 class="h3 mb-4"><i class="bi bi-play-circle me-2"></i>Executar Comandos</h1>
    </div>
</div>

<div class="row">
    <div class="col-md-4">
        <div class="card">
            <div class="card-header">
                <h5 class="card-title mb-0">Configuração</h5>
            </div>
            <div class="card-body">
                <form id="executeForm">
                    <div class="mb-3">
                        <label for="grupo_id" class="form-label">Grupo de Mikrotiks</label>
                        <select class="form-select" id="grupo_id" name="grupo_id" required>
                            <option value="">Selecione um grupo</option>
                            {% for grupo in grupos %}
                            <option value="{{ grupo.id }}">{{ grupo.nome }} ({{ grupo.mikrotiks|length }} hosts)</option>
                            {% endfor %}
                        </select>
                    </div>
                    
                    <div class="mb-3">
                        <label for="comando_id" class="form-label">Comando</label>
                        <select class="form-select" id="comando_id" name="comando_id" required>
                            <option value="">Selecione um comando</option>
                            {% for cmd in comandos %}
                            <option value="{{ cmd.id }}">{{ cmd.nome }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    
                    <button type="submit" class="btn btn-success w-100" id="executeBtn">
                        <i class="bi bi-play-fill me-1"></i>Executar
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5 class="card-title mb-0">Resultado da Execução</h5>
            </div>
            <div class="card-body">
                <div id="loading" class="text-center d-none">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Executando...</span>
                    </div>
                    <p class="mt-2">Executando comando...</p>
                </div>
                
                <div id="result" class="d-none">
                    <pre id="output"></pre>
                </div>
                
                <div id="noResult" class="text-muted">
                    Selecione um grupo e comando para executar.
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
document.getElementById('executeForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const grupoId = document.getElementById('grupo_id').value;
    const comandoId = document.getElementById('comando_id').value;
    
    if (!grupoId || !comandoId) {
        alert('Selecione um grupo e comando');
        return;
    }
    
    // Mostrar loading
    document.getElementById('loading').classList.remove('d-none');
    document.getElementById('result').classList.add('d-none');
    document.getElementById('noResult').classList.add('d-none');
    document.getElementById('executeBtn').disabled = true;
    
    try {
        const response = await fetch('/api/executar', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                grupo_id: parseInt(grupoId),
                comando_id: parseInt(comandoId)
            })
        });
        
        const data = await response.json();
        
        // Esconder loading
        document.getElementById('loading').classList.add('d-none');
        document.getElementById('result').classList.remove('d-none');
        
        // Mostrar resultado
        let output = '';
        if (data.error) {
            output = 'ERRO: ' + data.error;
        } else {
            output = 'STDOUT:\n' + (data.stdout || 'Nenhuma saída');
            if (data.stderr) {
                output += '\n\nSTDERR:\n' + data.stderr;
            }
            output += '\n\nCódigo de saída: ' + data.returncode;
        }
        
        document.getElementById('output').textContent = output;
        
    } catch (error) {
        document.getElementById('loading').classList.add('d-none');
        document.getElementById('result').classList.remove('d-none');
        document.getElementById('output').textContent = 'Erro na requisição: ' + error.message;
    }
    
    document.getElementById('executeBtn').disabled = false;
});
</script>
{% endblock %}
EOF

cat > templates/usuarios.html << 'EOF'
{% extends "base.html" %}
{% block title %}Usuários - Ansitrix{% endblock %}
{% block content %}
<div class="row">
    <div class="col-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3"><i class="bi bi-people me-2"></i>Usuários</h1>
            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addUserModal">
                <i class="bi bi-person-plus me-1"></i>Novo Usuário
            </button>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Usuário</th>
                        <th>Função</th>
                        <th>Criado em</th>
                        <th>Último Login</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in usuarios %}
                    <tr>
                        <td><strong>{{ user.username }}</strong></td>
                        <td>
                            {% if user.role == 'admin' %}
                                <span class="badge bg-danger">Administrador</span>
                            {% else %}
                                <span class="badge bg-secondary">Usuário</span>
                            {% endif %}
                        </td>
                        <td>{{ user.created_at.strftime('%d/%m/%Y') }}</td>
                        <td>
                            {% if user.last_login %}
                                {{ user.last_login.strftime('%d/%m/%Y %H:%M') }}
                            {% else %}
                                Nunca
                            {% endif %}
                        </td>
                        <td>
                            {% if user.username != 'admin' %}
                            <button class="btn btn-sm btn-outline-danger">
                                <i class="bi bi-trash"></i>
                            </button>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Modal -->
<div class="modal fade" id="addUserModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">Novo Usuário</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" action="{{ url_for('add_usuario') }}">
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="username" class="form-label">Nome de Usuário</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Senha</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <div class="mb-3">
                        <label for="role" class="form-label">Função</label>
                        <select class="form-select" id="role" name="role">
                            <option value="user">Usuário</option>
                            <option value="admin">Administrador</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Criar</button>
                </div>
            </form>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Criar serviço systemd
log "Configurando serviço systemd..."
sudo tee /etc/systemd/system/ansitrix.service > /dev/null << EOF
[Unit]
Description=Ansitrix Web Service - Gerenciamento Mikrotik via Ansible
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/ansitrix
Environment="PATH=/opt/ansitrix/venv/bin"
ExecStart=/opt/ansitrix/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar serviço
log "Habilitando e iniciando serviço..."
sudo systemctl daemon-reload
sudo systemctl enable ansitrix
sudo systemctl start ansitrix

# Configurar nginx (opcional)
log "Configurando Nginx como proxy reverso..."
sudo tee /etc/nginx/sites-available/ansitrix > /dev/null << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/ansitrix /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx

# Verificar se serviço está rodando
sleep 3
if systemctl is-active --quiet ansitrix; then
    log "✅ Serviço Ansitrix iniciado com sucesso!"
else
    error "❌ Falha ao iniciar o serviço Ansitrix"
    warn "Verificar logs com: sudo journalctl -u ansitrix -f"
fi

# Obter IP do servidor
IP=$(hostname -I | awk '{print $1}')

log "==============================================="
log "🎉 INSTALAÇÃO DO ANSITRIX CONCLUÍDA!"
log "==============================================="
log ""
log "📋 INFORMAÇÕES DE ACESSO:"
log "   URL: http://$IP (via Nginx)"
log "   URL Direta: http://$IP:5000"
log "   Usuário: admin"
log "   Senha: ChangeMe123!"
log ""
log "📁 LOCALIZAÇÃO DOS ARQUIVOS:"
log "   Aplicação: /opt/ansitrix/"
log "   Logs: sudo journalctl -u ansitrix -f"
log "   Banco: /opt/ansitrix/ansitrix.db"
log ""
log "🔧 COMANDOS ÚTEIS:"
log "   Reiniciar: sudo systemctl restart ansitrix"
log "   Parar: sudo systemctl stop ansitrix"
log "   Status: sudo systemctl status ansitrix"
log "   Logs: sudo journalctl -u ansitrix -f"
log ""
log "⚠️  IMPORTANTE:"
log "   - Altere a senha padrão após o primeiro login"
log "   - Configure as chaves SSH para acessar os Mikrotiks"
log "   - Para HTTPS, configure certificados SSL no Nginx"
log ""
warn "🔐 LEMBRE-SE DE ALTERAR A SENHA PADRÃO!"
log "==============================================="
