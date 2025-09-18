#!/bin/bash

# Script de instalação completa do Ansitrix
# Sistema de gerenciamento centralizado de Mikrotiks via Ansible
# Autor: Sistema Ansitrix
# Data: $(date +%Y-%m-%d)

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            ANSITRIX INSTALLER        ║${NC}"
echo -e "${BLUE}║   Mikrotik Management via Ansible    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════╝${NC}"
echo ""

# Verificar se é Ubuntu
if [[ ! -f /etc/lsb-release ]] || ! grep -q "Ubuntu" /etc/lsb-release; then
    echo -e "${RED}Este script é para Ubuntu. Sistema não suportado.${NC}"
    exit 1
fi

# Verificar se é executado como root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Este script deve ser executado como root. Execute: sudo ./install_ansitrix.sh${NC}"
   exit 1
fi

echo -e "${YELLOW}Atualizando sistema...${NC}"
sudo apt update && sudo apt upgrade -y

echo -e "${YELLOW}Instalando dependências do sistema...${NC}"
sudo apt install -y python3 python3-pip python3-venv git sshpass curl sqlite3 nginx

echo -e "${YELLOW}Criando estrutura de pastas...${NC}"
sudo mkdir -p /opt/ansitrix/{app,logs,ansible_playbooks,static/{css,js,images},templates,backup}
sudo chown -R $USER:$USER /opt/ansitrix

echo -e "${YELLOW}Criando ambiente virtual Python...${NC}"
python3 -m venv /opt/ansitrix/venv
source /opt/ansitrix/venv/bin/activate

echo -e "${YELLOW}Instalando pacotes Python...${NC}"
pip install --upgrade pip
pip install flask flask-login flask-wtf flask-migrate flask-sqlalchemy flask-bcrypt
pip install ansible ansible-runner paramiko netmiko requests pyyaml
pip install gunicorn python-dotenv cryptography

echo -e "${YELLOW}Criando arquivo de configuração...${NC}"
cat > /opt/ansitrix/app/config.py << 'EOF'
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24).hex()
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ansitrix.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    WTF_CSRF_ENABLED = True
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = '/opt/ansitrix/uploads'
EOF

echo -e "${YELLOW}Criando modelos de dados...${NC}"
cat > /opt/ansitrix/app/models.py << 'EOF'
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from cryptography.fernet import Fernet
import os

db = SQLAlchemy()

# Chave para criptografia de senhas (em produção, usar variável de ambiente)
CRYPTO_KEY = os.environ.get('CRYPTO_KEY', Fernet.generate_key())
cipher_suite = Fernet(CRYPTO_KEY)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'admin'

class MikrotikGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mikrotiks = db.relationship('Mikrotik', backref='group', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<MikrotikGroup {self.name}>'

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    ssh_port = db.Column(db.Integer, default=22)
    username = db.Column(db.String(100), nullable=False)
    password_encrypted = db.Column(db.Text, nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('mikrotik_group.id'), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_connected = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_encrypted = cipher_suite.encrypt(password.encode()).decode()

    def get_password(self):
        return cipher_suite.decrypt(self.password_encrypted.encode()).decode()

    def __repr__(self):
        return f'<Mikrotik {self.name}>'

class Command(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    command_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), default='general')
    requires_confirmation = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', backref='commands')

    def __repr__(self):
        return f'<Command {self.name}>'

class CommandExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    command_id = db.Column(db.Integer, db.ForeignKey('command.id'), nullable=False)
    mikrotik_id = db.Column(db.Integer, db.ForeignKey('mikrotik.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    output = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, running, success, failed
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    command = db.relationship('Command', backref='executions')
    mikrotik = db.relationship('Mikrotik', backref='executions')
    user = db.relationship('User', backref='executions')
EOF

echo -e "${YELLOW}Criando formulários...${NC}"
cat > /opt/ansitrix/app/forms.py << 'EOF'
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Length, Email, EqualTo
from app.models import MikrotikGroup, User

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Senha', validators=[DataRequired()])
    remember_me = BooleanField('Lembrar-me')
    submit = SubmitField('Entrar')

class MikrotikForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired(), Length(max=100)])
    ip = StringField('IP', validators=[DataRequired(), IPAddress()])
    ssh_port = IntegerField('Porta SSH', default=22, validators=[NumberRange(min=1, max=65535)])
    username = StringField('Usuário SSH', validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Senha SSH', validators=[DataRequired()])
    group_id = SelectField('Grupo', coerce=int, choices=[])
    submit = SubmitField('Salvar')

    def __init__(self, *args, **kwargs):
        super(MikrotikForm, self).__init__(*args, **kwargs)
        self.group_id.choices = [(0, 'Sem grupo')] + [(g.id, g.name) for g in MikrotikGroup.query.all()]

class GroupForm(FlaskForm):
    name = StringField('Nome do Grupo', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descrição', validators=[Length(max=200)])
    submit = SubmitField('Salvar')

class CommandForm(FlaskForm):
    name = StringField('Nome do Comando', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Descrição', validators=[Length(max=200)])
    command_text = TextAreaField('Comando', validators=[DataRequired()], render_kw={"rows": 5})
    category = SelectField('Categoria', choices=[
        ('general', 'Geral'),
        ('system', 'Sistema'),
        ('network', 'Rede'),
        ('user', 'Usuário'),
        ('backup', 'Backup')
    ])
    requires_confirmation = BooleanField('Requer confirmação')
    submit = SubmitField('Salvar')

class UserForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirmar Senha', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Função', choices=[('user', 'Usuário'), ('admin', 'Administrador')])
    submit = SubmitField('Salvar')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Senha Atual', validators=[DataRequired()])
    new_password = PasswordField('Nova Senha', validators=[DataRequired(), Length(min=6)])
    new_password2 = PasswordField('Confirmar Nova Senha', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Alterar Senha')
EOF

echo -e "${YELLOW}Criando runner do Ansible...${NC}"
cat > /opt/ansitrix/app/ansible_runner.py << 'EOF'
import ansible_runner
import tempfile
import os
import yaml
import json
from datetime import datetime

def create_inventory(mikrotiks):
    """Cria inventário temporário para os mikrotiks"""
    inventory = {'all': {'children': {'mikrotiks': {'hosts': {}}}}}
    
    for mikrotik in mikrotiks:
        inventory['all']['children']['mikrotiks']['hosts'][mikrotik.name] = {
            'ansible_host': mikrotik.ip,
            'ansible_port': mikrotik.ssh_port,
            'ansible_user': mikrotik.username,
            'ansible_ssh_pass': mikrotik.get_password(),
            'ansible_connection': 'ssh',
            'ansible_ssh_common_args': '-o StrictHostKeyChecking=no'
        }
    
    return inventory

def run_command_on_mikrotik(mikrotik, command_text):
    """Executa um comando em um mikrotik específico"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Criar inventário
        inventory = create_inventory([mikrotik])
        inventory_path = os.path.join(tmpdir, 'inventory.yml')
        
        with open(inventory_path, 'w') as f:
            yaml.dump(inventory, f)
        
        # Criar playbook
        playbook = [{
            'name': 'Execute command on Mikrotik',
            'hosts': 'mikrotiks',
            'gather_facts': False,
            'vars': {
                'ansible_python_interpreter': '/usr/bin/python3'
            },
            'tasks': [{
                'name': f'Execute: {command_text}',
                'raw': command_text,
                'register': 'command_result'
            }, {
                'name': 'Display result',
                'debug': {
                    'var': 'command_result'
                }
            }]
        }]
        
        playbook_path = os.path.join(tmpdir, 'playbook.yml')
        with open(playbook_path, 'w') as f:
            yaml.dump(playbook, f)
        
        # Executar
        try:
            r = ansible_runner.run(
                private_data_dir=tmpdir,
                playbook='playbook.yml',
                inventory=inventory_path,
                quiet=False,
                verbosity=1
            )
            
            result = {
                'status': 'success' if r.rc == 0 else 'failed',
                'return_code': r.rc,
                'stdout': r.stdout.read() if r.stdout else '',
                'stderr': r.stderr.read() if r.stderr else '',
                'started_at': str(datetime.now()),
                'finished_at': str(datetime.now())
            }
            
            return result
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'started_at': str(datetime.now()),
                'finished_at': str(datetime.now())
            }

def run_command_on_group(mikrotiks, command_text):
    """Executa um comando em um grupo de mikrotiks"""
    results = {}
    
    for mikrotik in mikrotiks:
        results[mikrotik.name] = run_command_on_mikrotik(mikrotik, command_text)
    
    return results
EOF

echo -e "${YELLOW}Criando aplicação principal...${NC}"
cat > /opt/ansitrix/app/app.py << 'EOF'
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

from config import Config
from models import db, User, Mikrotik, MikrotikGroup, Command, CommandExecution
from forms import LoginForm, MikrotikForm, GroupForm, CommandForm, UserForm, ChangePasswordForm
from ansible_runner import run_command_on_mikrotik, run_command_on_group

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas principais
@app.route('/')
@login_required
def dashboard():
    stats = {
        'mikrotiks_total': Mikrotik.query.count(),
        'mikrotiks_active': Mikrotik.query.filter_by(is_active=True).count(),
        'groups_total': MikrotikGroup.query.count(),
        'commands_total': Command.query.count(),
        'executions_today': CommandExecution.query.filter(
            CommandExecution.executed_at >= datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        ).count()
    }
    recent_executions = CommandExecution.query.order_by(CommandExecution.executed_at.desc()).limit(10).all()
    return render_template('dashboard.html', stats=stats, recent_executions=recent_executions)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.utcnow()
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        flash('Usuário inválido ou inativo', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout realizado com sucesso', 'success')
    return redirect(url_for('login'))

# Rotas para Mikrotiks
@app.route('/mikrotiks')
@login_required
def mikrotiks():
    page = request.args.get('page', 1, type=int)
    mikrotiks = Mikrotik.query.paginate(page=page, per_page=20, error_out=False)
    return render_template('mikrotiks.html', mikrotiks=mikrotiks)

@app.route('/mikrotiks/add', methods=['GET', 'POST'])
@login_required
def add_mikrotik():
    form = MikrotikForm()
    if form.validate_on_submit():
        mikrotik = Mikrotik(
            name=form.name.data,
            ip=form.ip.data,
            ssh_port=form.ssh_port.data,
            username=form.username.data,
            group_id=form.group_id.data if form.group_id.data != 0 else None
        )
        mikrotik.set_password(form.password.data)
        db.session.add(mikrotik)
        db.session.commit()
        flash('Mikrotik adicionado com sucesso', 'success')
        return redirect(url_for('mikrotiks'))
    return render_template('mikrotik_form.html', form=form, title='Adicionar Mikrotik')

@app.route('/mikrotiks/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_mikrotik(id):
    mikrotik = Mikrotik.query.get_or_404(id)
    form = MikrotikForm(obj=mikrotik)
    
    if form.validate_on_submit():
        mikrotik.name = form.name.data
        mikrotik.ip = form.ip.data
        mikrotik.ssh_port = form.ssh_port.data
        mikrotik.username = form.username.data
        if form.password.data:
            mikrotik.set_password(form.password.data)
        mikrotik.group_id = form.group_id.data if form.group_id.data != 0 else None
        db.session.commit()
        flash('Mikrotik atualizado com sucesso', 'success')
        return redirect(url_for('mikrotiks'))
    
    form.group_id.data = mikrotik.group_id or 0
    return render_template('mikrotik_form.html', form=form, title='Editar Mikrotik', mikrotik=mikrotik)

@app.route('/mikrotiks/<int:id>/delete', methods=['POST'])
@login_required
def delete_mikrotik(id):
    mikrotik = Mikrotik.query.get_or_404(id)
    db.session.delete(mikrotik)
    db.session.commit()
    flash('Mikrotik removido com sucesso', 'success')
    return redirect(url_for('mikrotiks'))

# Rotas para Grupos
@app.route('/groups')
@login_required
def groups():
    groups = MikrotikGroup.query.all()
    return render_template('groups.html', groups=groups)

@app.route('/groups/add', methods=['GET', 'POST'])
@login_required
def add_group():
    form = GroupForm()
    if form.validate_on_submit():
        group = MikrotikGroup(name=form.name.data, description=form.description.data)
        db.session.add(group)
        db.session.commit()
        flash('Grupo adicionado com sucesso', 'success')
        return redirect(url_for('groups'))
    return render_template('group_form.html', form=form, title='Adicionar Grupo')

# Rotas para Comandos
@app.route('/commands')
@login_required
def commands():
    commands = Command.query.all()
    return render_template('commands.html', commands=commands)

@app.route('/commands/add', methods=['GET', 'POST'])
@login_required
def add_command():
    form = CommandForm()
    if form.validate_on_submit():
        command = Command(
            name=form.name.data,
            description=form.description.data,
            command_text=form.command_text.data,
            category=form.category.data,
            requires_confirmation=form.requires_confirmation.data,
            created_by=current_user.id
        )
        db.session.add(command)
        db.session.commit()
        flash('Comando adicionado com sucesso', 'success')
        return redirect(url_for('commands'))
    return render_template('command_form.html', form=form, title='Adicionar Comando')

# Rota para execução de comandos
@app.route('/execute/<int:command_id>/<int:mikrotik_id>', methods=['POST'])
@login_required
def execute_command(command_id, mikrotik_id):
    command = Command.query.get_or_404(command_id)
    mikrotik = Mikrotik.query.get_or_404(mikrotik_id)
    
    execution = CommandExecution(
        command_id=command_id,
        mikrotik_id=mikrotik_id,
        user_id=current_user.id,
        status='running'
    )
    db.session.add(execution)
    db.session.commit()
    
    try:
        result = run_command_on_mikrotik(mikrotik, command.command_text)
        execution.output = str(result)
        execution.status = result['status']
        mikrotik.last_connected = datetime.utcnow()
    except Exception as e:
        execution.output = f"Erro: {str(e)}"
        execution.status = 'failed'
    
    db.session.commit()
    return jsonify({'execution_id': execution.id, 'status': execution.status})

@app.route('/execution/<int:execution_id>')
@login_required
def view_execution(execution_id):
    execution = CommandExecution.query.get_or_404(execution_id)
    return render_template('execution_result.html', execution=execution)

# Rotas para usuários (apenas admin)
@app.route('/users')
@login_required
def users():
    if not current_user.is_admin():
        flash('Acesso negado', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('users.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Criar usuário admin padrão se não existir
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@ansitrix.local', role='admin')
            admin.set_password('ChangeMe123!')
            db.session.add(admin)
            db.session.commit()
    
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

echo -e "${YELLOW}Criando templates HTML...${NC}"

# Base template
cat > /opt/ansitrix/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Ansitrix - Gerenciamento Mikrotik{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/style.css') }}" rel="stylesheet">
</head>
<body>
    <!-- Navbar -->
    {% if current_user.is_authenticated %}
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <img src="{{ url_for('static', filename='images/logo.svg') }}" alt="Ansitrix Logo" width="32" height="32" class="me-2">
                Ansitrix
            </a>
            
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('mikrotiks') }}"><i class="fas fa-router"></i> Mikrotiks</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('groups') }}"><i class="fas fa-layer-group"></i> Grupos</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('commands') }}"><i class="fas fa-terminal"></i> Comandos</a>
                    </li>
                    {% if current_user.is_admin() %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('users') }}"><i class="fas fa-users"></i> Usuários</a>
                    </li>
                    {% endif %}
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
                            <i class="fas fa-user"></i> {{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#"><i class="fas fa-cog"></i> Configurações</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}"><i class="fas fa-sign-out-alt"></i> Sair</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    {% endif %}

    <!-- Main content -->
    <div class="container-fluid py-4">
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>
</html>
EOF

# Login template
cat > /opt/ansitrix/templates/login.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-header text-center">
                <img src="{{ url_for('static', filename='images/logo.svg') }}" alt="Ansitrix" width="64" height="64" class="mb-3">
                <h4>Ansitrix Login</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    {{ form.hidden_tag() }}
                    
                    <div class="mb-3">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-control") }}
                    </div>
                    
                    <div class="mb-3">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-control") }}
                    </div>
                    
                    <div class="mb-3 form-check">
                        {{ form.remember_me(class="form-check-input") }}
                        {{ form.remember_me.label(class="form-check-label") }}
                    </div>
                    
                    <div class="d-grid">
                        {{ form.submit(class="btn btn-primary") }}
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
EOF

# Dashboard template
cat > /opt/ansitrix/templates/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row">
    <div class="col-12">
        <h1>Dashboard</h1>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-3">
        <div class="card text-white bg-primary">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.mikrotiks_total }}</h4>
                        <p class="mb-0">Mikrotiks Total</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-router fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-success">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.mikrotiks_active }}</h4>
                        <p class="mb-0">Mikrotiks Ativos</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-check-circle fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-info">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.groups_total }}</h4>
                        <p class="mb-0">Grupos</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-layer-group fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="card text-white bg-warning">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h4>{{ stats.executions_today }}</h4>
                        <p class="mb-0">Execuções Hoje</p>
                    </div>
                    <div class="align-self-center">
                        <i class="fas fa-play fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-12">
        <div class="card">
            <div class="card-header">
                <h5>Execuções Recentes</h5>
            </div>
            <div class="card-body">
                {% if recent_executions %}
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Data/Hora</th>
                                <th>Mikrotik</th>
                                <th>Comando</th>
                                <th>Status</th>
                                <th>Usuário</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for execution in recent_executions %}
                            <tr>
                                <td>{{ execution.executed_at.strftime('%d/%m/%Y %H:%M') }}</td>
                                <td>{{ execution.mikrotik.name }}</td>
                                <td>{{ execution.command.name }}</td>
                                <td>
                                    <span class="badge bg-{{ 'success' if execution.status == 'success' else 'danger' }}">
                                        {{ execution.status }}
                                    </span>
                                </td>
                                <td>{{ execution.user.username }}</td>
                                <td>
                                    <a href="{{ url_for('view_execution', execution_id=execution.id) }}" class="btn btn-sm btn-outline-primary">
                                        <i class="fas fa-eye"></i> Ver
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <p class="text-muted">Nenhuma execução recente</p>
                {% endif %}
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Mikrotiks template
cat > /opt/ansitrix/templates/mikrotiks.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h1>Mikrotiks</h1>
    <a href="{{ url_for('add_mikrotik') }}" class="btn btn-primary">
        <i class="fas fa-plus"></i> Adicionar Mikrotik
    </a>
</div>

<div class="card">
    <div class="card-body">
        {% if mikrotiks.items %}
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Nome</th>
                        <th>IP</th>
                        <th>Porta SSH</th>
                        <th>Usuário</th>
                        <th>Grupo</th>
                        <th>Status</th>
                        <th>Última Conexão</th>
                        <th>Ações</th>
                    </tr>
                </thead>
                <tbody>
                    {% for mikrotik in mikrotiks.items %}
                    <tr>
                        <td>{{ mikrotik.name }}</td>
                        <td>{{ mikrotik.ip }}</td>
                        <td>{{ mikrotik.ssh_port }}</td>
                        <td>{{ mikrotik.username }}</td>
                        <td>{{ mikrotik.group.name if mikrotik.group else 'Sem grupo' }}</td>
                        <td>
                            <span class="badge bg-{{ 'success' if mikrotik.is_active else 'secondary' }}">
                                {{ 'Ativo' if mikrotik.is_active else 'Inativo' }}
                            </span>
                        </td>
                        <td>{{ mikrotik.last_connected.strftime('%d/%m/%Y %H:%M') if mikrotik.last_connected else 'Nunca' }}</td>
                        <td>
                            <div class="btn-group" role="group">
                                <a href="{{ url_for('edit_mikrotik', id=mikrotik.id) }}" class="btn btn-sm btn-outline-primary">
                                    <i class="fas fa-edit"></i>
                                </a>
                                <form method="POST" action="{{ url_for('delete_mikrotik', id=mikrotik.id) }}" class="d-inline">
                                    <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Confirma a remoção?')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <!-- Paginação -->
        {% if mikrotiks.pages > 1 %}
        <nav aria-label="Page navigation">
            <ul class="pagination justify-content-center">
                {% if mikrotiks.has_prev %}
                <li class="page-item">
                    <a class="page-link" href="{{ url_for('mikrotiks', page=mikrotiks.prev_num) }}">Anterior</a>
                </li>
                {% endif %}
                
                {% for page_num in mikrotiks.iter_pages() %}
                    {% if page_num %}
                        {% if page_num != mikrotiks.page %}
                        <li class="page-item">
                            <a class="page-link" href="{{ url_for('mikrotiks', page=page_num) }}">{{ page_num }}</a>
                        </li>
                        {% else %}
                        <li class="page-item active">
                            <span class="page-link">{{ page_num }}</span>
                        </li>
                        {% endif %}
                    {% else %}
                    <li class="page-item disabled">
                        <span class="page-link">...</span>
                    </li>
                    {% endif %}
                {% endfor %}
                
                {% if mikrotiks.has_next %}
                <li class="page-item">
                    <a class="page-link" href="{{ url_for('mikrotiks', page=mikrotiks.next_num) }}">Próximo</a>
                </li>
                {% endif %}
            </ul>
        </nav>
        {% endif %}
        
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-router fa-3x text-muted mb-3"></i>
            <h5>Nenhum Mikrotik cadastrado</h5>
            <p class="text-muted">Comece adicionando seu primeiro Mikrotik</p>
            <a href="{{ url_for('add_mikrotik') }}" class="btn btn-primary">
                <i class="fas fa-plus"></i> Adicionar Mikrotik
            </a>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}
EOF

# Form template genérico
cat > /opt/ansitrix/templates/mikrotik_form.html << 'EOF'
{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-8">
        <div class="card">
            <div class="card-header">
                <h4>{{ title }}</h4>
            </div>
            <div class="card-body">
                <form method="POST">
                    {{ form.hidden_tag() }}
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.name.label(class="form-label") }}
                                {{ form.name(class="form-control") }}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.ip.label(class="form-label") }}
                                {{ form.ip(class="form-control") }}
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.ssh_port.label(class="form-label") }}
                                {{ form.ssh_port(class="form-control") }}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.group_id.label(class="form-label") }}
                                {{ form.group_id(class="form-select") }}
                            </div>
                        </div>
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.username.label(class="form-label") }}
                                {{ form.username(class="form-control") }}
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                {{ form.password.label(class="form-label") }}
                                {{ form.password(class="form-control") }}
                                {% if mikrotik %}
                                <div class="form-text">Deixe em branco para manter a senha atual</div>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    
                    <div class="d-flex gap-2">
                        {{ form.submit(class="btn btn-primary") }}
                        <a href="{{ url_for('mikrotiks') }}" class="btn btn-secondary">Cancelar</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

echo -e "${YELLOW}Criando arquivos CSS e JavaScript...${NC}"

cat > /opt/ansitrix/static/css/style.css << 'EOF'
:root {
    --ansitrix-primary: #0052cc;
    --ansitrix-secondary: #6c757d;
    --ansitrix-success: #28a745;
    --ansitrix-danger: #dc3545;
    --ansitrix-warning: #ffc107;
    --ansitrix-info: #17a2b8;
    --ansitrix-light: #f8f9fa;
    --ansitrix-dark: #343a40;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--ansitrix-light);
}

.navbar-brand img {
    filter: brightness(0) invert(1);
}

.card {
    border: none;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    border-radius: 0.5rem;
}

.btn {
    border-radius: 0.375rem;
}

.table {
    border-radius: 0.5rem;
    overflow: hidden;
}

.badge {
    border-radius: 0.375rem;
}

/* Loading spinner */
.spinner {
    display: inline-block;
    width: 20px;
    height: 20px;
    border: 3px solid rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    border-top-color: #fff;
    animation: spin 1s ease-in-out infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

/* Custom scrollbar */
::-webkit-scrollbar {
    width: 8px;
}

::-webkit-scrollbar-track {
    background: #f1f1f1;
}

::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
}

::-webkit-scrollbar-thumb:hover {
    background: #555;
}
EOF

cat > /opt/ansitrix/static/js/main.js << 'EOF'
// Ansitrix Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Confirm delete actions
    const deleteButtons = document.querySelectorAll('[data-confirm-delete]');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            if (!confirm('Tem certeza que deseja excluir este item?')) {
                e.preventDefault();
            }
        });
    });

    // Execute command with loading state
    const executeButtons = document.querySelectorAll('.execute-command');
    executeButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const commandId = this.dataset.commandId;
            const mikrotikId = this.dataset.mikrotikId;
            const originalText = this.innerHTML;
            
            // Set loading state
            this.innerHTML = '<span class="spinner"></span> Executando...';
            this.disabled = true;
            
            fetch(`/execute/${commandId}/${mikrotikId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                // Redirect to execution result
                window.location.href = `/execution/${data.execution_id}`;
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Erro ao executar comando');
                this.innerHTML = originalText;
                this.disabled = false;
            });
        });
    });
});

// Utility functions
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    document.body.appendChild(container);
    return container;
}
EOF

echo -e "${YELLOW}Criando logo SVG...${NC}"
cat > /opt/ansitrix/static/images/logo.svg << 'EOF'
<svg width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" fill="none">
  <!-- Orbit ellipse -->
  <ellipse cx="32" cy="32" rx="28" ry="15" stroke="#0052cc" stroke-width="1.5" stroke-opacity="0.4" fill="none" transform="rotate(-15 32 32)"/>
  
  <!-- Comet body -->
  <circle cx="45" cy="25" r="4" fill="#0052cc"/>
  <circle cx="45" cy="25" r="2.5" fill="#ffffff" opacity="0.8"/>
  
  <!-- Comet tail -->
  <path d="M41 27 Q30 35 20 40" stroke="#0052cc" stroke-width="2" stroke-linecap="round" opacity="0.6"/>
  <path d="M42 29 Q32 36 24 40" stroke="#0052cc" stroke-width="1.5" stroke-linecap="round" opacity="0.4"/>
  <path d="M43 31 Q35 37 28 40" stroke="#0052cc" stroke-width="1" stroke-linecap="round" opacity="0.2"/>
  
  <!-- Central hub -->
  <circle cx="32" cy="32" r="6" fill="none" stroke="#0052cc" stroke-width="2"/>
  <circle cx="32" cy="32" r="3" fill="#0052cc"/>
  
  <!-- Connection lines (representing network) -->
  <line x1="32" y1="26" x2="32" y2="15" stroke="#0052cc" stroke-width="1.5" opacity="0.5"/>
  <line x1="38" y1="32" x2="49" y2="32" stroke="#0052cc" stroke-width="1.5" opacity="0.5"/>
  <line x1="26" y1="32" x2="15" y2="32" stroke="#0052cc" stroke-width="1.5" opacity="0.5"/>
  <line x1="32" y1="38" x2="32" y2="49" stroke="#0052cc" stroke-width="1.5" opacity="0.5"/>
  
  <!-- Small nodes -->
  <circle cx="32" cy="15" r="2" fill="#0052cc" opacity="0.7"/>
  <circle cx="49" cy="32" r="2" fill="#0052cc" opacity="0.7"/>
  <circle cx="15" cy="32" r="2" fill="#0052cc" opacity="0.7"/>
  <circle cx="32" cy="49" r="2" fill="#0052cc" opacity="0.7"/>
</svg>
EOF

echo -e "${YELLOW}Criando script de inicialização do banco...${NC}"
cat > /opt/ansitrix/app/init_db.py << 'EOF'
#!/usr/bin/env python3

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, MikrotikGroup, Command

def init_database():
    """Inicializa o banco de dados com dados básicos"""
    with app.app_context():
        # Criar tabelas
        db.create_all()
        
        # Criar usuário admin se não existir
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@ansitrix.local',
                role='admin'
            )
            admin.set_password('ChangeMe123!')
            db.session.add(admin)
            print("Usuário admin criado: admin / ChangeMe123!")
        
        # Criar grupo padrão
        default_group = MikrotikGroup.query.filter_by(name='Default').first()
        if not default_group:
            default_group = MikrotikGroup(
                name='Default',
                description='Grupo padrão para Mikrotiks'
            )
            db.session.add(default_group)
        
        # Criar comandos básicos
        basic_commands = [
            {
                'name': 'System Reboot',
                'description': 'Reinicia o sistema Mikrotik',
                'command_text': '/system reboot',
                'category': 'system',
                'requires_confirmation': True
            },
            {
                'name': 'System Info',
                'description': 'Mostra informações do sistema',
                'command_text': '/system resource print',
                'category': 'system',
                'requires_confirmation': False
            },
            {
                'name': 'Interface List',
                'description': 'Lista todas as interfaces',
                'command_text': '/interface print',
                'category': 'network',
                'requires_confirmation': False
            },
            {
                'name': 'Export Configuration',
                'description': 'Exporta a configuração completa',
                'command_text': '/export',
                'category': 'backup',
                'requires_confirmation': False
            },
            {
                'name': 'User List',
                'description': 'Lista todos os usuários',
                'command_text': '/user print',
                'category': 'user',
                'requires_confirmation': False
            },
            {
                'name': 'IP Address List',
                'description': 'Lista endereços IP configurados',
                'command_text': '/ip address print',
                'category': 'network',
                'requires_confirmation': False
            }
        ]
        
        for cmd_data in basic_commands:
            cmd = Command.query.filter_by(name=cmd_data['name']).first()
            if not cmd:
                cmd = Command(
                    name=cmd_data['name'],
                    description=cmd_data['description'],
                    command_text=cmd_data['command_text'],
                    category=cmd_data['category'],
                    requires_confirmation=cmd_data['requires_confirmation'],
                    created_by=admin.id
                )
                db.session.add(cmd)
        
        db.session.commit()
        print("Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    init_database()
EOF

echo -e "${YELLOW}Criando arquivos restantes...${NC}"

# Criar templates restantes básicos
mkdir -p /opt/ansitrix/templates
touch /opt/ansitrix/templates/groups.html
touch /opt/ansitrix/templates/group_form.html
touch /opt/ansitrix/templates/commands.html
touch /opt/ansitrix/templates/command_form.html
touch /opt/ansitrix/templates/users.html
touch /opt/ansitrix/templates/execution_result.html

# Criar arquivo __init__.py
touch /opt/ansitrix/app/__init__.py

echo -e "${YELLOW}Configurando permissões...${NC}"
sudo chown -R $USER:$USER /opt/ansitrix
chmod +x /opt/ansitrix/app/init_db.py

echo -e "${YELLOW}Inicializando banco de dados...${NC}"
cd /opt/ansitrix/app
source ../venv/bin/activate
python3 init_db.py

echo -e "${YELLOW}Configurando serviço systemd...${NC}"
cat > /tmp/ansitrix.service << EOF
[Unit]
Description=Ansitrix Mikrotik Management System
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/ansitrix/app
Environment=PATH=/opt/ansitrix/venv/bin
ExecStart=/opt/ansitrix/venv/bin/python /opt/ansitrix/app/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/ansitrix.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ansitrix
sudo systemctl start ansitrix

echo -e "${YELLOW}Configurando Nginx (opcional)...${NC}"
cat > /tmp/ansitrix-nginx << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo mv /tmp/ansitrix-nginx /etc/nginx/sites-available/ansitrix
sudo ln -sf /etc/nginx/sites-available/ansitrix /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Aguardar alguns segundos para o serviço iniciar
echo -e "${YELLOW}Aguardando serviço inicializar...${NC}"
sleep 10

# Obter IP da máquina
IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 INSTALAÇÃO CONCLUÍDA!                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}🌐 ACESSO À APLICAÇÃO:${NC}"
echo -e "${YELLOW}   URL: http://$IP${NC}"
echo -e "${YELLOW}   Porta alternativa: http://$IP:5000${NC}"
echo ""
echo -e "${BLUE}👤 CREDENCIAIS PADRÃO:${NC}"
echo -e "${YELLOW}   Usuário: admin${NC}"
echo -e "${YELLOW}   Senha: ChangeMe123!${NC}"
echo ""
echo -e "${RED}⚠️  IMPORTANTE:${NC}"
echo -e "${YELLOW}   - Altere a senha padrão após o primeiro login${NC}"
echo -e "${YELLOW}   - Configure um firewall adequado${NC}"
echo -e "${YELLOW}   - Para produção, use HTTPS com certificado SSL${NC}"
echo ""
echo -e "${BLUE}📋 COMANDOS ÚTEIS:${NC}"
echo -e "${YELLOW}   - Status do serviço: sudo systemctl status ansitrix${NC}"
echo -e "${YELLOW}   - Ver logs: sudo journalctl -u ansitrix -f${NC}"
echo -e "${YELLOW}   - Reiniciar: sudo systemctl restart ansitrix${NC}"
echo ""
echo -e "${GREEN}Ansitrix está pronto para gerenciar seus Mikrotiks!${NC}"
