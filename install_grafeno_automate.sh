#!/bin/bash

# Script de instalação automática do Grafeno Automate
# Sistema de gerenciamento de Mikrotiks com Ansible

set -e

echo "=========================================="
echo "    GRAFENO AUTOMATE - INSTALAÇÃO"
echo "=========================================="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para log
log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Verificar se é root
if [ "$EUID" -ne 0 ]; then
    error "Execute este script como root (sudo ./install_grafeno_automate.sh)"
fi

# Atualizar sistema
log "Atualizando sistema..."
apt update && apt upgrade -y

# Instalar dependências básicas
log "Instalando dependências básicas..."
apt install python3 python3-pip python3-venv nginx git curl openssl -y

# Criar usuário para a aplicação (se não existir)
if ! id "grafeno" &>/dev/null; then
    log "Criando usuário grafeno..."
    useradd -m -s /bin/bash grafeno
fi

# Criar diretório da aplicação
APP_DIR="/opt/grafeno_automate"
log "Criando diretório da aplicação em $APP_DIR..."
mkdir -p $APP_DIR
cd $APP_DIR

# Gerar chave secreta para Flask
SECRET_KEY=$(openssl rand -hex 32)
log "Chave secreta gerada"

# Gerar senha forte para admin
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
log "Senha do admin gerada: $ADMIN_PASSWORD"

# Criar ambiente virtual
log "Criando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

# Criar requirements.txt
log "Criando requirements.txt..."
cat > requirements.txt << EOF
flask==2.3.3
flask-login==0.6.3
flask_sqlalchemy==3.0.5
ansible==8.5.0
netmiko==4.2.0
paramiko==3.3.1
gunicorn==21.2.0
bcrypt==4.0.1
werkzeug==2.3.7
EOF

# Instalar dependências Python
log "Instalando dependências Python..."
pip install --upgrade pip
pip install -r requirements.txt

# Criar estrutura de diretórios
log "Criando estrutura de diretórios..."
mkdir -p templates static/css static/js ansible_playbooks logs

# Criar aplicação principal
log "Criando aplicação principal..."
cat > app.py << 'EOF'
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from netmiko import ConnectHandler
import os
import logging
from datetime import datetime
import subprocess
import json

# Configuração da aplicação
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grafeno_automate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração de logs
logging.basicConfig(
    filename='logs/grafeno_automate.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='unknown')

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mikrotiks = db.relationship('Mikrotik', backref='grupo', lazy=True)

class ComandoRapido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    command = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LogExecucao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mikrotik_id = db.Column(db.Integer, db.ForeignKey('mikrotik.id'))
    comando_id = db.Column(db.Integer, db.ForeignKey('comando_rapido.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    output = db.Column(db.Text)
    status = db.Column(db.String(20))
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            app.logger.info(f'Login realizado: {user.username}')
            return redirect(url_for('dashboard'))
        flash('Usuário ou senha inválidos', 'error')
        app.logger.warning(f'Tentativa de login inválida: {request.form["username"]}')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    app.logger.info(f'Logout realizado: {current_user.username}')
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    mikrotiks = Mikrotik.query.all()
    grupos = Grupo.query.all()
    comandos = ComandoRapido.query.all()
    logs_recentes = LogExecucao.query.order_by(LogExecucao.executed_at.desc()).limit(10).all()
    
    stats = {
        'total_mikrotiks': len(mikrotiks),
        'total_grupos': len(grupos),
        'total_comandos': len(comandos)
    }
    
    return render_template('dashboard.html', 
                         mikrotiks=mikrotiks, 
                         grupos=grupos, 
                         comandos=comandos,
                         logs_recentes=logs_recentes,
                         stats=stats)

@app.route('/mikrotik/add', methods=['GET', 'POST'])
@login_required
def add_mikrotik():
    if request.method == 'POST':
        m = Mikrotik(
            name=request.form['name'],
            ip=request.form['ip'],
            username=request.form['username'],
            password=request.form['password'],
            grupo_id=request.form.get('grupo_id') if request.form.get('grupo_id') else None
        )
        db.session.add(m)
        db.session.commit()
        flash('Mikrotik adicionado com sucesso!', 'success')
        app.logger.info(f'Mikrotik adicionado: {m.name} ({m.ip}) por {current_user.username}')
        return redirect(url_for('dashboard'))
    
    grupos = Grupo.query.all()
    return render_template('add_mikrotik.html', grupos=grupos)

@app.route('/grupo/add', methods=['GET', 'POST'])
@login_required
def add_grupo():
    if request.method == 'POST':
        g = Grupo(
            name=request.form['name'],
            description=request.form.get('description', '')
        )
        db.session.add(g)
        db.session.commit()
        flash('Grupo criado com sucesso!', 'success')
        app.logger.info(f'Grupo criado: {g.name} por {current_user.username}')
        return redirect(url_for('dashboard'))
    return render_template('add_grupo.html')

@app.route('/comando/add', methods=['GET', 'POST'])
@login_required
def add_comando():
    if request.method == 'POST':
        c = ComandoRapido(
            name=request.form['name'],
            command=request.form['command'],
            description=request.form.get('description', '')
        )
        db.session.add(c)
        db.session.commit()
        flash('Comando rápido adicionado com sucesso!', 'success')
        app.logger.info(f'Comando adicionado: {c.name} por {current_user.username}')
        return redirect(url_for('dashboard'))
    return render_template('add_comando.html')

@app.route('/executar/<int:mikrotik_id>/<int:comando_id>')
@login_required
def executar(mikrotik_id, comando_id):
    mikrotik = Mikrotik.query.get_or_404(mikrotik_id)
    comando = ComandoRapido.query.get_or_404(comando_id)

    device = {
        'device_type': 'mikrotik_routeros',
        'host': mikrotik.ip,
        'username': mikrotik.username,
        'password': mikrotik.password,
        'timeout': 20,
        'session_timeout': 60
    }
    
    log_exec = LogExecucao(
        mikrotik_id=mikrotik_id,
        comando_id=comando_id,
        user_id=current_user.id
    )
    
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_command(comando.command)
        net_connect.disconnect()
        
        log_exec.output = output
        log_exec.status = 'success'
        
        flash(f'Comando "{comando.name}" executado com sucesso em {mikrotik.name}!', 'success')
        app.logger.info(f'Comando executado: {comando.name} em {mikrotik.name} por {current_user.username}')
        
    except Exception as e:
        log_exec.output = str(e)
        log_exec.status = 'error'
        
        flash(f'Erro ao executar comando em {mikrotik.name}: {str(e)}', 'error')
        app.logger.error(f'Erro ao executar comando: {comando.name} em {mikrotik.name} - {str(e)}')
    
    db.session.add(log_exec)
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/mikrotik/<int:mikrotik_id>/delete')
@login_required
def delete_mikrotik(mikrotik_id):
    mikrotik = Mikrotik.query.get_or_404(mikrotik_id)
    name = mikrotik.name
    db.session.delete(mikrotik)
    db.session.commit()
    flash(f'Mikrotik "{name}" removido com sucesso!', 'success')
    app.logger.info(f'Mikrotik removido: {name} por {current_user.username}')
    return redirect(url_for('dashboard'))

@app.route('/comando/<int:comando_id>/delete')
@login_required
def delete_comando(comando_id):
    comando = ComandoRapido.query.get_or_404(comando_id)
    name = comando.name
    db.session.delete(comando)
    db.session.commit()
    flash(f'Comando "{name}" removido com sucesso!', 'success')
    app.logger.info(f'Comando removido: {name} por {current_user.username}')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

# Criar templates HTML
log "Criando templates HTML..."

# Base template
cat > templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Grafeno Automate{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="{{ url_for('static', filename='css/grafeno.css') }}">
</head>
<body>
    <div class="container-fluid">
        {% if current_user.is_authenticated %}
        <nav class="navbar navbar-expand-lg navbar-dark bg-grafeno mb-4">
            <div class="container">
                <a class="navbar-brand fw-bold" href="{{ url_for('dashboard') }}">GRAFENO AUTOMATE</a>
                <div class="navbar-nav ms-auto">
                    <span class="navbar-text me-3">Olá, {{ current_user.username }}</span>
                    <a class="btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Sair</a>
                </div>
            </div>
        </nav>
        {% endif %}

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Login template
cat > templates/login.html << 'EOF'
{% extends "base.html" %}
{% block title %}Login - Grafeno Automate{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow grafeno-card">
            <div class="card-body">
                <div class="text-center mb-4">
                    <h2 class="card-title text-grafeno fw-bold">GRAFENO AUTOMATE</h2>
                    <p class="text-muted">Sistema de Gerenciamento Mikrotik</p>
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
                    <button type="submit" class="btn btn-grafeno w-100">Entrar</button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Dashboard template
cat > templates/dashboard.html << 'EOF'
{% extends "base.html" %}
{% block title %}Dashboard - Grafeno Automate{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-md-4">
        <div class="card bg-grafeno text-white">
            <div class="card-body">
                <h5 class="card-title">Mikrotiks</h5>
                <h2>{{ stats.total_mikrotiks }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card bg-secondary text-white">
            <div class="card-body">
                <h5 class="card-title">Grupos</h5>
                <h2>{{ stats.total_grupos }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card bg-info text-white">
            <div class="card-body">
                <h5 class="card-title">Comandos</h5>
                <h2>{{ stats.total_comandos }}</h2>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header d-flex justify-content-between">
                <h5>Mikrotiks</h5>
                <a href="{{ url_for('add_mikrotik') }}" class="btn btn-primary btn-sm">Adicionar</a>
            </div>
            <div class="card-body">
                {% if mikrotiks %}
                    {% for m in mikrotiks %}
                    <div class="d-flex justify-content-between align-items-center border-bottom py-2">
                        <div>
                            <strong>{{ m.name }}</strong><br>
                            <small class="text-muted">{{ m.ip }}{% if m.grupo %} - {{ m.grupo.name }}{% endif %}</small>
                        </div>
                        <div>
                            {% for c in comandos %}
                                <a href="{{ url_for('executar', mikrotik_id=m.id, comando_id=c.id) }}" 
                                   class="btn btn-outline-primary btn-sm me-1">{{ c.name }}</a>
                            {% endfor %}
                            <a href="{{ url_for('delete_mikrotik', mikrotik_id=m.id) }}" 
                               class="btn btn-outline-danger btn-sm"
                               onclick="return confirm('Tem certeza?')">Remover</a>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted">Nenhum Mikrotik cadastrado</p>
                {% endif %}
            </div>
        </div>
    </div>

    <div class="col-md-6">
        <div class="card">
            <div class="card-header d-flex justify-content-between">
                <h5>Comandos Rápidos</h5>
                <a href="{{ url_for('add_comando') }}" class="btn btn-primary btn-sm">Adicionar</a>
            </div>
            <div class="card-body">
                {% if comandos %}
                    {% for c in comandos %}
                    <div class="d-flex justify-content-between align-items-center border-bottom py-2">
                        <div>
                            <strong>{{ c.name }}</strong><br>
                            <small class="text-muted">{{ c.command[:50] }}...</small>
                        </div>
                        <a href="{{ url_for('delete_comando', comando_id=c.id) }}" 
                           class="btn btn-outline-danger btn-sm"
                           onclick="return confirm('Tem certeza?')">Remover</a>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted">Nenhum comando cadastrado</p>
                {% endif %}
            </div>
        </div>

        <div class="card mt-3">
            <div class="card-header d-flex justify-content-between">
                <h5>Grupos</h5>
                <a href="{{ url_for('add_grupo') }}" class="btn btn-primary btn-sm">Adicionar</a>
            </div>
            <div class="card-body">
                {% if grupos %}
                    {% for g in grupos %}
                    <div class="border-bottom py-2">
                        <strong>{{ g.name }}</strong> ({{ g.mikrotiks|length }} mikrotiks)
                        {% if g.description %}<br><small class="text-muted">{{ g.description }}</small>{% endif %}
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-muted">Nenhum grupo cadastrado</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Add Mikrotik template
cat > templates/add_mikrotik.html << 'EOF'
{% extends "base.html" %}
{% block title %}Adicionar Mikrotik - Grafeno Automate{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>Adicionar Mikrotik</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="name" class="form-label">Nome</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="ip" class="form-label">IP</label>
                        <input type="text" class="form-control" id="ip" name="ip" required>
                    </div>
                    <div class="mb-3">
                        <label for="username" class="form-label">Usuário</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Senha</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <div class="mb-3">
                        <label for="grupo_id" class="form-label">Grupo (opcional)</label>
                        <select class="form-control" id="grupo_id" name="grupo_id">
                            <option value="">Selecione um grupo</option>
                            {% for grupo in grupos %}
                                <option value="{{ grupo.id }}">{{ grupo.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">Salvar</button>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancelar</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Add Grupo template
cat > templates/add_grupo.html << 'EOF'
{% extends "base.html" %}
{% block title %}Adicionar Grupo - Grafeno Automate{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>Adicionar Grupo</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="name" class="form-label">Nome</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="description" class="form-label">Descrição</label>
                        <textarea class="form-control" id="description" name="description" rows="3"></textarea>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">Salvar</button>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancelar</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Add Comando template
cat > templates/add_comando.html << 'EOF'
{% extends "base.html" %}
{% block title %}Adicionar Comando - Grafeno Automate{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h5>Adicionar Comando Rápido</h5>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="name" class="form-label">Nome</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="mb-3">
                        <label for="command" class="form-label">Comando RouterOS</label>
                        <textarea class="form-control" id="command" name="command" rows="4" required></textarea>
                        <small class="form-text text-muted">Exemplo: /system reboot</small>
                    </div>
                    <div class="mb-3">
                        <label for="description" class="form-label">Descrição</label>
                        <textarea class="form-control" id="description" name="description" rows="2"></textarea>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="submit" class="btn btn-primary">Salvar</button>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Cancelar</a>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-header">
                <h6>Comandos Sugeridos</h6>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <strong>Reboot</strong><br>
                        <code>/system reboot</code>
                    </div>
                    <div class="col-md-6">
                        <strong>Export Config</strong><br>
                        <code>/export file=backup</code>
                    </div>
                </div>
                <div class="row mt-2">
                    <div class="col-md-6">
                        <strong>Add User</strong><br>
                        <code>/user add name=novo_user group=read password=senha123</code>
                    </div>
                    <div class="col-md-6">
                        <strong>Show Users</strong><br>
                        <code>/user print</code>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Criar CSS
log "Criando arquivos CSS..."
cat > static/css/grafeno.css << 'EOF'
:root {
    --grafeno-primary: #2c3e50;
    --grafeno-secondary: #34495e;
    --grafeno-accent: #3498db;
    --grafeno-success: #27ae60;
    --grafeno-warning: #f39c12;
    --grafeno-danger: #e74c3c;
    --grafeno-light: #ecf0f1;
    --grafeno-dark: #2c3e50;
}

body {
    background-color: #f8f9fa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.bg-grafeno {
    background-color: var(--grafeno-primary) !important;
}

.text-grafeno {
    color: var(--grafeno-primary) !important;
}

.btn-grafeno {
    background-color: var(--grafeno-primary);
    border-color: var(--grafeno-primary);
    color: white;
}

.btn-grafeno:hover {
    background-color: var(--grafeno-secondary);
    border-color: var(--grafeno-secondary);
    color: white;
}

.grafeno-card {
    border: none;
    border-radius: 10px;
    margin-top: 100px;
}

.navbar-brand {
    font-size: 1.5rem;
    letter-spacing: 1px;
}

.card {
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.card-header {
    background-color: var(--grafeno-light);
    border-bottom: 1px solid #dee2e6;
    font-weight: 600;
}

.btn-outline-primary {
    border-color: var(--grafeno-accent);
    color: var(--grafeno-accent);
}

.btn-outline-primary:hover {
    background-color: var(--grafeno-accent);
    border-color: var(--grafeno-accent);
}

.alert-success {
    background-color: #d4edda;
    border-color: #c3e6cb;
    color: #155724;
}

.alert-danger {
    background-color: #f8d7da;
    border-color: #f5c6cb;
    color: #721c24;
}

code {
    background-color: #f8f9fa;
    padding: 2px 4px;
    border-radius: 3px;
    font-size: 0.9em;
}
EOF

# Criar script de inicialização do banco
log "Criando script de inicialização..."
cat > init_db.py << EOF
#!/usr/bin/env python3
import os
import sys
from app import app, db, User, ComandoRapido

def init_database():
    with app.app_context():
        # Criar todas as tabelas
        db.create_all()
        
        # Verificar se já existe usuário admin
        if not User.query.filter_by(username='grafeno').first():
            # Criar usuário admin
            admin = User(username='grafeno')
            admin.set_password('$ADMIN_PASSWORD')
            db.session.add(admin)
            
            # Adicionar comandos padrão
            comandos_padrao = [
                {
                    'name': 'Reboot',
                    'command': '/system reboot',
                    'description': 'Reinicia o sistema Mikrotik'
                },
                {
                    'name': 'Export Config',
                    'command': '/export file=backup_config',
                    'description': 'Exporta a configuração completa para arquivo'
                },
                {
                    'name': 'Show Users',
                    'command': '/user print',
                    'description': 'Lista todos os usuários do sistema'
                },
                {
                    'name': 'Show Version',
                    'command': '/system resource print',
                    'description': 'Mostra informações do sistema e recursos'
                },
                {
                    'name': 'Show IP Addresses',
                    'command': '/ip address print',
                    'description': 'Lista todos os endereços IP configurados'
                },
                {
                    'name': 'Show Interfaces',
                    'command': '/interface print',
                    'description': 'Lista todas as interfaces de rede'
                },
                {
                    'name': 'Show Routes',
                    'command': '/ip route print',
                    'description': 'Lista a tabela de roteamento'
                },
                {
                    'name': 'Show DHCP Leases',
                    'command': '/ip dhcp-server lease print',
                    'description': 'Lista os leases do servidor DHCP'
                }
            ]
            
            for cmd_data in comandos_padrao:
                cmd = ComandoRapido(**cmd_data)
                db.session.add(cmd)
            
            db.session.commit()
            print("✅ Banco de dados inicializado com sucesso!")
            print(f"👤 Usuário: grafeno")
            print(f"🔑 Senha: $ADMIN_PASSWORD")
            print(f"📝 {len(comandos_padrao)} comandos rápidos adicionados")
        else:
            print("ℹ️  Banco de dados já inicializado")

if __name__ == '__main__':
    init_database()
EOF

# Criar arquivo de configuração systemd
log "Criando serviço systemd..."
cat > /etc/systemd/system/grafeno-automate.service << EOF
[Unit]
Description=Grafeno Automate - Sistema de Gerenciamento Mikrotik
After=network.target

[Service]
Type=exec
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
Environment="SECRET_KEY=$SECRET_KEY"
ExecStart=$APP_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Configurar Nginx
log "Configurando Nginx..."
cat > /etc/nginx/sites-available/grafeno-automate << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /opt/grafeno_automate/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Logs
    access_log /var/log/nginx/grafeno-automate_access.log;
    error_log /var/log/nginx/grafeno-automate_error.log;
}
EOF

# Ativar site no Nginx
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/grafeno-automate /etc/nginx/sites-enabled/

# Testar configuração do Nginx
nginx -t

# Alterar permissões
chown -R root:root $APP_DIR
chmod +x init_db.py

# Inicializar banco de dados
log "Inicializando banco de dados..."
cd $APP_DIR
source venv/bin/activate
python3 init_db.py

# Habilitar e iniciar serviços
log "Habilitando e iniciando serviços..."
systemctl daemon-reload
systemctl enable grafeno-automate
systemctl start grafeno-automate
systemctl restart nginx

# Verificar status dos serviços
log "Verificando status dos serviços..."
sleep 3

if systemctl is-active --quiet grafeno-automate; then
    log "✅ Serviço Grafeno Automate está rodando"
else
    error "❌ Falha ao iniciar serviço Grafeno Automate"
fi

if systemctl is-active --quiet nginx; then
    log "✅ Nginx está rodando"
else
    error "❌ Falha ao iniciar Nginx"
fi

# Configurar firewall (se estiver ativo)
if systemctl is-active --quiet ufw; then
    log "Configurando firewall..."
    ufw allow 80/tcp
    ufw allow 22/tcp
    ufw --force enable
fi

# Informações finais
log "=========================================="
log "    GRAFENO AUTOMATE - INSTALAÇÃO CONCLUÍDA"
log "=========================================="
log ""
log "🌐 Acesse: http://$(hostname -I | awk '{print $1}')"
log "👤 Usuário: grafeno"
log "🔑 Senha: $ADMIN_PASSWORD"
log ""
log "📁 Diretório da aplicação: $APP_DIR"
log "📊 Logs da aplicação: $APP_DIR/logs/"
log "📊 Logs do Nginx: /var/log/nginx/"
log ""
log "🔧 Comandos úteis:"
log "   Reiniciar aplicação: systemctl restart grafeno-automate"
log "   Ver logs: journalctl -u grafeno-automate -f"
log "   Status: systemctl status grafeno-automate"
log ""
log "⚠️  IMPORTANTE: Anote a senha acima, ela não será exibida novamente!"
log ""

# Salvar credenciais em arquivo
echo "=========================================" > $APP_DIR/CREDENCIAIS.txt
echo "GRAFENO AUTOMATE - CREDENCIAIS DE ACESSO" >> $APP_DIR/CREDENCIAIS.txt
echo "=========================================" >> $APP_DIR/CREDENCIAIS.txt
echo "URL: http://$(hostname -I | awk '{print $1}')" >> $APP_DIR/CREDENCIAIS.txt
echo "Usuário: grafeno" >> $APP_DIR/CREDENCIAIS.txt
echo "Senha: $ADMIN_PASSWORD" >> $APP_DIR/CREDENCIALS.txt
echo "Data da instalação: $(date)" >> $APP_DIR/CREDENCIALS.txt
echo "=========================================" >> $APP_DIR/CREDENCIALS.txt

log "💾 Credenciais salvas em: $APP_DIR/CREDENCIALS.txt"
EOF

---

## 2. Como usar

### 2.1. Baixe e execute o script:

```bash
# Baixar o script
wget https://raw.githubusercontent.com/seuusuario/grafeno-automate/main/install_grafeno_automate.sh

# Ou crie o arquivo manualmente e cole o conteúdo
nano install_grafeno_automate.sh

# Dar permissão de execução
chmod +x install_grafeno_automate.sh

# Executar como root
sudo ./install_grafeno_automate.sh
