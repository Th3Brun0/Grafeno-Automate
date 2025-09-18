#!/bin/bash

set -e

echo "=========================================="
echo "     ANSITRIX INSTALLATION SCRIPT"
echo "=========================================="

# ==========================================
# PARTE 1: SISTEMA E DEPENDÊNCIAS
# ==========================================

echo "Iniciando instalação do Ansitrix..."
echo "Parte 1: Atualizando sistema e instalando dependências..."

# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependências básicas
sudo apt install -y python3 python3-pip python3-venv git nginx sqlite3 fail2ban ufw curl

# Instalar Ansible e bibliotecas Python necessárias
sudo pip3 install --upgrade pip
sudo pip3 install ansible paramiko netmiko flask flask-login flask-bcrypt flask-wtf flask_sqlalchemy cryptography

# Criar usuário ansitrix para rodar a aplicação
if ! id -u ansitrix >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash ansitrix
fi

# Criar diretórios da aplicação
APP_DIR="/opt/ansitrix"
sudo mkdir -p $APP_DIR
sudo chown ansitrix:ansitrix $APP_DIR

# Estrutura de pastas
sudo -u ansitrix mkdir -p $APP_DIR/{templates,static/css,static/js,logs,ansible,backups}

echo "Parte 1 concluída: sistema atualizado e estrutura criada."

# ==========================================
# PARTE 2: BACKEND PYTHON
# ==========================================

echo "Parte 2: Criando ambiente virtual e backend Python..."

cd $APP_DIR

# Criar ambiente virtual Python
sudo -u ansitrix python3 -m venv venv
sudo -u ansitrix ./venv/bin/pip install --upgrade pip
sudo -u ansitrix ./venv/bin/pip install ansible paramiko netmiko flask flask-login flask-bcrypt flask-wtf flask_sqlalchemy cryptography

# Criar arquivo principal app.py
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/app.py > /dev/null
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('ANSITRIX_SECRET_KEY', 'change_this_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ansitrix.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

FERNET_KEY = os.environ.get('ANSITRIX_FERNET_KEY')
if not FERNET_KEY:
    FERNET_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()
fernet = Fernet(FERNET_KEY.encode())

user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

mikrotik_groups = db.Table('mikrotik_groups',
    db.Column('mikrotik_id', db.Integer, db.ForeignKey('mikrotik.id')),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(50), default='user')
    groups = db.relationship('Group', secondary=user_groups, backref='users')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    ssh_port = db.Column(db.Integer, default=22)
    ssh_user = db.Column(db.String(150), nullable=False)
    ssh_password_encrypted = db.Column(db.LargeBinary, nullable=False)
    groups = db.relationship('Group', secondary=mikrotik_groups, backref='mikrotiks')

    def set_password(self, password):
        self.ssh_password_encrypted = fernet.encrypt(password.encode())

    def get_password(self):
        return fernet.decrypt(self.ssh_password_encrypted).decode()

class Command(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    command_text = db.Column(db.Text, nullable=False)

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class RegisterUserForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Confirme a Senha', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Permissão', choices=[('admin', 'Administrador'), ('user', 'Usuário')])
    submit = SubmitField('Cadastrar')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Usuário já existe.')

class MikrotikForm(FlaskForm):
    name = StringField('Nome do Mikrotik', validators=[DataRequired()])
    ip = StringField('IP', validators=[DataRequired()])
    ssh_port = IntegerField('Porta SSH', default=22, validators=[NumberRange(min=1, max=65535)])
    ssh_user = StringField('Usuário SSH', validators=[DataRequired()])
    ssh_password = PasswordField('Senha SSH', validators=[DataRequired()])
    groups = StringField('Grupos (separados por vírgula)')
    submit = SubmitField('Salvar')

class CommandForm(FlaskForm):
    name = StringField('Nome do Comando', validators=[DataRequired()])
    command_text = TextAreaField('Comando', validators=[DataRequired()])
    submit = SubmitField('Salvar')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def users():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    form = RegisterUserForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Usuário cadastrado com sucesso.', 'success')
        return redirect(url_for('users'))
    return render_template('add_user.html', form=form)

@app.route('/mikrotiks')
@login_required
def mikrotiks():
    mikrotiks = Mikrotik.query.all()
    return render_template('mikrotiks.html', mikrotiks=mikrotiks)

@app.route('/mikrotiks/add', methods=['GET', 'POST'])
@login_required
def add_mikrotik():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    form = MikrotikForm()
    if form.validate_on_submit():
        mikrotik = Mikrotik(
            name=form.name.data,
            ip=form.ip.data,
            ssh_port=form.ssh_port.data,
            ssh_user=form.ssh_user.data
        )
        mikrotik.set_password(form.ssh_password.data)
        if form.groups.data:
            group_names = [g.strip() for g in form.groups.data.split(',') if g.strip()]
            for gname in group_names:
                group = Group.query.filter_by(name=gname).first()
                if not group:
                    group = Group(name=gname)
                    db.session.add(group)
                mikrotik.groups.append(group)
        db.session.add(mikrotik)
        db.session.commit()
        flash('Mikrotik cadastrado com sucesso.', 'success')
        return redirect(url_for('mikrotiks'))
    return render_template('add_mikrotik.html', form=form)

@app.route('/commands')
@login_required
def commands():
    commands = Command.query.all()
    return render_template('commands.html', commands=commands)

@app.route('/commands/add', methods=['GET', 'POST'])
@login_required
def add_command():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'danger')
        return redirect(url_for('index'))
    form = CommandForm()
    if form.validate_on_submit():
        cmd = Command(name=form.name.data, command_text=form.command_text.data)
        db.session.add(cmd)
        db.session.commit()
        flash('Comando cadastrado com sucesso.', 'success')
        return redirect(url_for('commands'))
    return render_template('add_command.html', form=form)

@app.route('/execute', methods=['GET', 'POST'])
@login_required
def execute():
    if request.method == 'POST':
        mikrotik_id = request.form.get('mikrotik_id')
        command_id = request.form.get('command_id')
        mikrotik = Mikrotik.query.get(mikrotik_id)
        command = Command.query.get(command_id)
        if not mikrotik or not command:
            return jsonify({'status': 'error', 'message': 'Mikrotik ou comando inválido.'})
        result = run_ansible_command(mikrotik, command.command_text)
        return jsonify({'status': 'success', 'output': result})
    else:
        mikrotiks = Mikrotik.query.all()
        commands = Command.query.all()
        return render_template('execute.html', mikrotiks=mikrotiks, commands=commands)

def run_ansible_command(mikrotik, command_text):
    inventory_path = os.path.join(app.root_path, 'ansible', 'inventory.ini')
    with open(inventory_path, 'w') as f:
        f.write(f"[mikrotiks]\n{mikrotik.ip} ansible_port={mikrotik.ssh_port} ansible_user={mikrotik.ssh_user} ansible_ssh_pass={mikrotik.get_password()} ansible_connection=ssh ansible_python_interpreter=/usr/bin/python3\n")

    playbook_path = os.path.join(app.root_path, 'ansible', 'playbook.yml')
    playbook_content = f"""---
- hosts: mikrotiks
  gather_facts: no
  tasks:
    - name: Executar comando Mikrotik
      ansible.builtin.raw: '{command_text}'
      register: output
    - name: Mostrar resultado
      debug:
        var: output.stdout
"""
    with open(playbook_path, 'w') as f:
        f.write(playbook_content)

    cmd = f"./venv/bin/ansible-playbook -i {inventory_path} {playbook_path} --ssh-extra-args='-o StrictHostKeyChecking=no'"

    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, cwd=app.root_path, timeout=60)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return e.output.decode()
    except Exception as e:
        return str(e)

def create_tables():
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', role='admin')
            admin.set_password('ansitrix123')
            db.session.add(admin)
            db.session.commit()

if __name__ == '__main__':
    create_tables()
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

echo "Parte 2 concluída: backend Python criado."

# ==========================================
# PARTE 3: TEMPLATES HTML E CSS
# ==========================================

echo "Parte 3: Criando templates HTML e CSS..."

# Base template
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/base.html > /dev/null
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Ansitrix - {% block title %}{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}" />
    <script>
        function toggleTheme() {
            const body = document.body;
            if(body.classList.contains('dark')) {
                body.classList.remove('dark');
                localStorage.setItem('theme', 'light');
            } else {
                body.classList.add('dark');
                localStorage.setItem('theme', 'dark');
            }
        }
        window.onload = function() {
            if(localStorage.getItem('theme') === 'dark') {
                document.body.classList.add('dark');
            }
        }
    </script>
</head>
<body>
    <nav>
        <div class="logo">
            <svg width="40" height="40" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="32" cy="32" r="30" stroke="#007ACC" stroke-width="3"/>
                <path d="M10 54L54 10" stroke="#007ACC" stroke-width="3" stroke-linecap="round"/>
                <circle cx="54" cy="10" r="6" fill="#007ACC"/>
                <path d="M40 24L54 10L48 16" stroke="#007ACC" stroke-width="2" stroke-linejoin="round"/>
            </svg>
            <span>Ansitrix</span>
        </div>
        <ul>
            {% if current_user.is_authenticated %}
            <li><a href="{{ url_for('index') }}">Início</a></li>
            <li><a href="{{ url_for('mikrotiks') }}">Mikrotiks</a></li>
            <li><a href="{{ url_for('commands') }}">Comandos</a></li>
            {% if current_user.role == 'admin' %}
            <li><a href="{{ url_for('users') }}">Usuários</a></li>
            {% endif %}
            <li><a href="{{ url_for('execute') }}">Executar</a></li>
            <li><a href="{{ url_for('logout') }}">Sair</a></li>
            {% else %}
            <li><a href="{{ url_for('login') }}">Login</a></li>
            {% endif %}
            <li><button onclick="toggleTheme()" class="btn-theme">Tema</button></li>
        </ul>
    </nav>
    <main>
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            <div class="flash-messages">
              {% for category, message in messages %}
                <div class="flash {{ category }}">{{ message }}</div>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </main>
</body>
</html>
EOF

# Login page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/login.html > /dev/null
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="login-container">
    <h2>Login no Ansitrix</h2>
    <form method="POST" action="{{ url_for('login') }}">
        {{ form.hidden_tag() }}
        <div class="form-group">
            <label for="username">Usuário</label>
            {{ form.username(class="form-control") }}
        </div>
        <div class="form-group">
            <label for="password">Senha</label>
            {{ form.password(class="form-control") }}
        </div>
        {{ form.submit(class="btn btn-primary") }}
    </form>
</div>
{% endblock %}
EOF

# Index page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/index.html > /dev/null
{% extends "base.html" %}
{% block title %}Início{% endblock %}
{% block content %}
<div class="dashboard">
    <h1>Bem-vindo ao Ansitrix</h1>
    <p>Sistema de gerenciamento centralizado de Mikrotiks via Ansible</p>
    
    <div class="dashboard-cards">
        <div class="card">
            <h3>Mikrotiks</h3>
            <p>Gerencie seus equipamentos Mikrotik</p>
            <a href="{{ url_for('mikrotiks') }}" class="btn">Acessar</a>
        </div>
        
        <div class="card">
            <h3>Comandos</h3>
            <p>Configure comandos predefinidos</p>
            <a href="{{ url_for('commands') }}" class="btn">Acessar</a>
        </div>
        
        <div class="card">
            <h3>Executar</h3>
            <p>Execute comandos nos equipamentos</p>
            <a href="{{ url_for('execute') }}" class="btn btn-primary">Executar</a>
        </div>
        
        {% if current_user.role == 'admin' %}
        <div class="card">
            <h3>Usuários</h3>
            <p>Gerencie usuários do sistema</p>
            <a href="{{ url_for('users') }}" class="btn">Acessar</a>
        </div>
        {% endif %}
    </div>
</div>
{% endblock %}
EOF

# Users page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/users.html > /dev/null
{% extends "base.html" %}
{% block title %}Usuários{% endblock %}
{% block content %}
<div class="page-header">
    <h2>Usuários</h2>
    <a href="{{ url_for('add_user') }}" class="btn btn-primary">Adicionar Usuário</a>
</div>

<table class="data-table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Usuário</th>
            <th>Permissão</th>
        </tr>
    </thead>
    <tbody>
        {% for user in users %}
        <tr>
            <td>{{ user.id }}</td>
            <td>{{ user.username }}</td>
            <td>{{ user.role }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
EOF

# Add user page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/add_user.html > /dev/null
{% extends "base.html" %}
{% block title %}Adicionar Usuário{% endblock %}
{% block content %}
<h2>Adicionar Usuário</h2>
<form method="POST" action="{{ url_for('add_user') }}">
    {{ form.hidden_tag() }}
    
    <div class="form-group">
        <label for="username">{{ form.username.label }}</label>
        {{ form.username(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="password">{{ form.password.label }}</label>
        {{ form.password(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="password2">{{ form.password2.label }}</label>
        {{ form.password2(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="role">{{ form.role.label }}</label>
        {{ form.role(class="form-control") }}
    </div>
    
    {{ form.submit(class="btn btn-primary") }}
    <a href="{{ url_for('users') }}" class="btn btn-secondary">Cancelar</a>
</form>
{% endblock %}
EOF

# Mikrotiks page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/mikrotiks.html > /dev/null
{% extends "base.html" %}
{% block title %}Mikrotiks{% endblock %}
{% block content %}
<div class="page-header">
    <h2>Mikrotiks</h2>
    {% if current_user.role == 'admin' %}
    <a href="{{ url_for('add_mikrotik') }}" class="btn btn-primary">Adicionar Mikrotik</a>
    {% endif %}
</div>

<table class="data-table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Nome</th>
            <th>IP</th>
            <th>Porta SSH</th>
            <th>Usuário</th>
            <th>Grupos</th>
        </tr>
    </thead>
    <tbody>
        {% for mikrotik in mikrotiks %}
        <tr>
            <td>{{ mikrotik.id }}</td>
            <td>{{ mikrotik.name }}</td>
            <td>{{ mikrotik.ip }}</td>
            <td>{{ mikrotik.ssh_port }}</td>
            <td>{{ mikrotik.ssh_user }}</td>
            <td>
                {% for group in mikrotik.groups %}
                    <span class="badge">{{ group.name }}</span>
                {% endfor %}
            </td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
EOF

# Add mikrotik page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/add_mikrotik.html > /dev/null
{% extends "base.html" %}
{% block title %}Adicionar Mikrotik{% endblock %}
{% block content %}
<h2>Adicionar Mikrotik</h2>
<form method="POST" action="{{ url_for('add_mikrotik') }}">
    {{ form.hidden_tag() }}
    
    <div class="form-group">
        <label for="name">{{ form.name.label }}</label>
        {{ form.name(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="ip">{{ form.ip.label }}</label>
        {{ form.ip(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="ssh_port">{{ form.ssh_port.label }}</label>
        {{ form.ssh_port(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="ssh_user">{{ form.ssh_user.label }}</label>
        {{ form.ssh_user(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="ssh_password">{{ form.ssh_password.label }}</label>
        {{ form.ssh_password(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="groups">{{ form.groups.label }}</label>
        {{ form.groups(class="form-control", placeholder="Ex: producao, backup") }}
        <small>Separe os grupos por vírgula</small>
    </div>
    
    {{ form.submit(class="btn btn-primary") }}
    <a href="{{ url_for('mikrotiks') }}" class="btn btn-secondary">Cancelar</a>
</form>
{% endblock %}
EOF

# Commands page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/commands.html > /dev/null
{% extends "base.html" %}
{% block title %}Comandos{% endblock %}
{% block content %}
<div class="page-header">
    <h2>Comandos</h2>
    {% if current_user.role == 'admin' %}
    <a href="{{ url_for('add_command') }}" class="btn btn-primary">Adicionar Comando</a>
    {% endif %}
</div>

<table class="data-table">
    <thead>
        <tr>
            <th>ID</th>
            <th>Nome</th>
            <th>Comando</th>
        </tr>
    </thead>
    <tbody>
        {% for command in commands %}
        <tr>
            <td>{{ command.id }}</td>
            <td>{{ command.name }}</td>
            <td><code>{{ command.command_text[:50] }}{% if command.command_text|length > 50 %}...{% endif %}</code></td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% endblock %}
EOF

# Add command page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/add_command.html > /dev/null
{% extends "base.html" %}
{% block title %}Adicionar Comando{% endblock %}
{% block content %}
<h2>Adicionar Comando</h2>
<form method="POST" action="{{ url_for('add_command') }}">
    {{ form.hidden_tag() }}
    
    <div class="form-group">
        <label for="name">{{ form.name.label }}</label>
        {{ form.name(class="form-control") }}
    </div>
    
    <div class="form-group">
        <label for="command_text">{{ form.command_text.label }}</label>
        {{ form.command_text(class="form-control", rows="5") }}
    </div>
    
    {{ form.submit(class="btn btn-primary") }}
    <a href="{{ url_for('commands') }}" class="btn btn-secondary">Cancelar</a>
</form>

<div class="command-examples">
    <h3>Exemplos de Comandos Importantes:</h3>
    <ul>
        <li><strong>Reboot:</strong> <code>/system reboot</code></li>
        <li><strong>Export Config:</strong> <code>/export</code></li>
        <li><strong>Add User:</strong> <code>/user add name=usuario password=senha group=full</code></li>
        <li><strong>Remove User:</strong> <code>/user remove usuario</code></li>
        <li><strong>List Interfaces:</strong> <code>/interface print</code></li>
        <li><strong>System Info:</strong> <code>/system resource print</code></li>
    </ul>
</div>
{% endblock %}
EOF

# Execute page
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/templates/execute.html > /dev/null
{% extends "base.html" %}
{% block title %}Executar Comandos{% endblock %}
{% block content %}
<h2>Executar Comandos</h2>

<form id="executeForm">
    <div class="form-group">
        <label for="mikrotik">Selecionar Mikrotik:</label>
        <select name="mikrotik_id" id="mikrotik" class="form-control" required>
            <option value="">Selecione um Mikrotik</option>
            {% for mikrotik in mikrotiks %}
            <option value="{{ mikrotik.id }}">{{ mikrotik.name }} ({{ mikrotik.ip }})</option>
            {% endfor %}
        </select>
    </div>
    
    <div class="form-group">
        <label for="command">Selecionar Comando:</label>
        <select name="command_id" id="command" class="form-control" required>
            <option value="">Selecione um comando</option>
            {% for command in commands %}
            <option value="{{ command.id }}">{{ command.name }}</option>
            {% endfor %}
        </select>
    </div>
    
    <button type="submit" class="btn btn-primary">Executar</button>
</form>

<div id="output" class="output-container" style="display:none;">
    <h3>Resultado da Execução:</h3>
    <pre id="outputContent"></pre>
</div>

<script>
document.getElementById('executeForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const formData = new FormData(this);
    const outputDiv = document.getElementById('output');
    const outputContent = document.getElementById('outputContent');
    
    outputDiv.style.display = 'block';
    outputContent.textContent = 'Executando comando...';
    
    fetch('/execute', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            outputContent.textContent = data.output;
        } else {
            outputContent.textContent = 'Erro: ' + data.message;
        }
    })
    .catch(error => {
        outputContent.textContent = 'Erro de conexão: ' + error;
    });
});
</script>
{% endblock %}
EOF

# CSS profissional
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/static/css/style.css > /dev/null
:root {
    --primary-color: #007ACC;
    --secondary-color: #005A9E;
    --background-color: #FFFFFF;
    --surface-color: #F8F9FA;
    --text-color: #212529;
    --text-secondary: #6C757D;
    --border-color: #DEE2E6;
    --shadow: 0 2px 8px rgba(0,0,0,0.1);
    --success-color: #28A745;
    --danger-color: #DC3545;
    --warning-color: #FFC107;
}

body.dark {
    --background-color: #1A1A1A;
    --surface-color: #2D2D2D;
    --text-color: #FFFFFF;
    --text-secondary: #B0B0B0;
    --border-color: #404040;
    --shadow: 0 2px 8px rgba(0,0,0,0.3);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background-color: var(--background-color);
    color: var(--text-color);
    line-height: 1.6;
    transition: all 0.3s ease;
}

nav {
    background-color: var(--surface-color);
    padding: 1rem 2rem;
    box-shadow: var(--shadow);
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
}

.logo {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 1.5rem;
    font-weight: bold;
    color: var(--primary-color);
}

nav ul {
    display: flex;
    list-style: none;
    gap: 1rem;
    align-items: center;
}

nav a {
    color: var(--text-color);
    text-decoration: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    transition: all 0.2s ease;
}

nav a:hover {
    background-color: var(--primary-color);
    color: white;
}

.btn-theme {
    background: var(--primary-color);
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s ease;
}

.btn-theme:hover {
    background: var(--secondary-color);
}

main {
    max-width: 1200px;
    margin: 2rem auto;
    padding: 0 2rem;
}

.btn {
    display: inline-block;
    padding: 0.75rem 1.5rem;
    background-color: var(--primary-color);
    color: white;
    text-decoration: none;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 1rem;
    transition: all 0.2s ease;
    text-align: center;
}

.btn:hover {
    background-color: var(--secondary-color);
    transform: translateY(-1px);
}

.btn-primary { background-color: var(--primary-color); }
.btn-secondary { background-color: var(--text-secondary); }
.btn-success { background-color: var(--success-color); }
.btn-danger { background-color: var(--danger-color); }

.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: var(--text-color);
}

.form-control {
    width: 100%;
    padding: 0.75rem;
    border: 2px solid var(--border-color);
    border-radius: 6px;
    background-color: var(--background-color);
    color: var(--text-color);
    font-size: 1rem;
    transition: border-color 0.2s ease;
}

.form-control:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(0, 122, 204, 0.1);
}

.data-table {
    width: 100%;
    border-collapse: collapse;
    background-color: var(--surface-color);
    border-radius: 8px;
    overflow: hidden;
    box-shadow: var(--shadow);
}

.data-table th,
.data-table td {
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

.data-table th {
    background-color: var(--primary-color);
    color: white;
    font-weight: 600;
}

.data-table tbody tr:hover {
    background-color: var(--border-color);
}

.dashboard-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 2rem;
    margin-top: 2rem;
}

.card {
    background-color: var(--surface-color);
    padding: 2rem;
    border-radius: 12px;
    box-shadow: var(--shadow);
    text-align: center;
    transition: transform 0.2s ease;
}

.card:hover {
    transform: translateY(-4px);
}

.card h3 {
    color: var(--primary-color);
    margin-bottom: 1rem;
}

.page-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 2px solid var(--border-color);
}

.flash-messages {
    margin-bottom: 2rem;
}

.flash {
    padding: 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
    font-weight: 500;
}

.flash.success {
    background-color: #D4EDDA;
    color: #155724;
    border: 1px solid #C3E6CB;
}

.flash.danger {
    background-color: #F8D7DA;
    color: #721C24;
    border: 1px solid #F5C6CB;
}

body.dark .flash.success {
    background-color: #1C4A2E;
    color: #A7D6B7;
}

body.dark .flash.danger {
    background-color: #4A1C1C;
    color: #D6A7A7;
}

code {
    background-color: var(--border-color);
    padding: 0.2rem 0.4rem;
    border-radius: 4px;
    font-family: 'Courier New', monospace;
}

.output-container {
    margin-top: 2rem;
    background-color: var(--surface-color);
    border-radius: 8px;
    padding: 1rem;
    border: 1px solid var(--border-color);
}

.output-container pre {
    background-color: var(--background-color);
    padding: 1rem;
    border-radius: 4px;
    overflow-x: auto;
    white-space: pre-wrap;
    border: 1px solid var(--border-color);
}

.badge {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    background-color: var(--primary-color);
    color: white;
    font-size: 0.75rem;
    border-radius: 12px;
    margin-right: 0.25rem;
}

.command-examples {
    margin-top: 2rem;
    background-color: var(--surface-color);
    padding: 1.5rem;
    border-radius: 8px;
    border-left: 4px solid var(--primary-color);
}

.command-examples ul {
    list-style-type: none;
    padding-left: 0;
}

.command-examples li {
    margin-bottom: 0.5rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border-color);
}

.login-container {
    max-width: 400px;
    margin: 4rem auto;
    padding: 2rem;
    background-color: var(--surface-color);
    border-radius: 12px;
    box-shadow: var(--shadow);
}

.login-container h2 {
    text-align: center;
    margin-bottom: 2rem;
    color: var(--primary-color);
}

@media (max-width: 768px) {
    nav {
        flex-direction: column;
        gap: 1rem;
    }
    
    nav ul {
        flex-wrap: wrap;
        justify-content: center;
    }
    
    .page-header {
        flex-direction: column;
        gap: 1rem;
    }
    
    .dashboard-cards {
        grid-template-columns: 1fr;
    }
    
    main {
        padding: 0 1rem;
    }
}
EOF

# Criar comandos importantes
cat << 'EOF' | sudo -u ansitrix tee $APP_DIR/init_commands.py > /dev/null
#!/usr/bin/env python3
import sys
import os
sys.path.append('/opt/ansitrix')

from app import app, db, Command

important_commands = [
    {"name": "Reboot System", "command_text": "/system reboot"},
    {"name": "Export Configuration", "command_text": "/export"},
    {"name": "System Resource Info", "command_text": "/system resource print"},
    {"name": "Interface List", "command_text": "/interface print"},
    {"name": "IP Address List", "command_text": "/ip address print"},
    {"name": "Firewall Rules", "command_text": "/ip firewall filter print"},
    {"name": "User List", "command_text": "/user print"},
    {"name": "System Identity", "command_text": "/system identity print"},
    {"name": "System Backup", "command_text": "/system backup save name=backup"},
    {"name": "System Update Check", "command_text": "/system package update check-for-updates"}
]

with app.app_context():
    db.create_all()
    for cmd_data in important_commands:
        existing_cmd = Command.query.filter_by(name=cmd_data["name"]).first()
        if not existing_cmd:
            cmd = Command(name=cmd_data["name"], command_text=cmd_data["command_text"])
            db.session.add(cmd)
    db.session.commit()
    print("Comandos importantes adicionados ao banco de dados.")
EOF

sudo chmod +x $APP_DIR/init_commands.py
cd $APP_DIR && sudo -u ansitrix ./venv/bin/python init_commands.py

echo "Parte 3 concluída: templates HTML, CSS e comandos criados."

# ==========================================
# PARTE 4: CONFIGURAÇÃO DO SISTEMA
# ==========================================

echo "Parte 4: Configurando sistema, nginx, firewall e segurança..."

# Configuração do Nginx
cat << 'EOF' | sudo tee /etc/nginx/sites-available/ansitrix > /dev/null
server {
    listen 80;
    server_name _;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    limit_req_zone $binary_remote_addr zone=ansitrix:10m rate=10r/s;
    limit_req zone=ansitrix burst=20 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    location /static {
        alias /opt/ansitrix/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/ansitrix /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# Gerar chaves seguras
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
FERNET_KEY=$(python3 -c 'import base64; import os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())')

# Service do systemd
cat << EOF | sudo tee /etc/systemd/system/ansitrix.service > /dev/null
[Unit]
Description=Ansitrix - Mikrotik Management Tool
After=network.target

[Service]
Type=simple
User=ansitrix
Group=ansitrix
WorkingDirectory=/opt/ansitrix
Environment=ANSITRIX_SECRET_KEY=$SECRET_KEY
Environment=ANSITRIX_FERNET_KEY=$FERNET_KEY
ExecStart=/opt/ansitrix/venv/bin/python app.py
Restart=always
RestartSec=3

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/ansitrix

[Install]
WantedBy=multi-user.target
EOF

# Configurar fail2ban
cat << 'EOF' | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 10
EOF

# Script de backup
cat << 'EOF' | sudo tee /opt/ansitrix/backup.sh > /dev/null
#!/bin/bash
BACKUP_DIR="/opt/ansitrix/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

cp /opt/ansitrix/ansitrix.db $BACKUP_DIR/ansitrix_$DATE.db
tar -czf $BACKUP_DIR/logs_$DATE.tar.gz /opt/ansitrix/logs/ 2>/dev/null || true

find $BACKUP_DIR -name "ansitrix_*.db" -mtime +7 -delete
find $BACKUP_DIR -name "logs_*.tar.gz" -mtime +7 -delete

echo "Backup realizado: $DATE"
EOF

sudo chmod +x /opt/ansitrix/backup.sh
sudo chown ansitrix:ansitrix /opt/ansitrix/backup.sh

# Cron job para backup diário
echo "0 2 * * * /opt/ansitrix/backup.sh >> /opt/ansitrix/logs/backup.log 2>&1" | sudo -u ansitrix crontab -

# Configurar firewall
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable

# Definir permissões finais
sudo -u ansitrix mkdir -p /opt/ansitrix/logs
sudo -u ansitrix touch /opt/ansitrix/logs/app.log
sudo chmod 755 /opt/ansitrix
sudo chmod 644 /opt/ansitrix/*.py
sudo chmod 644 /opt/ansitrix/templates/*
sudo chmod 644 /opt/ansitrix/static/css/*
sudo chown -R ansitrix:ansitrix /opt/ansitrix

# Habilitar e iniciar serviços
sudo systemctl daemon-reload
sudo systemctl enable ansitrix
sudo systemctl start ansitrix
sudo systemctl enable nginx
sudo systemctl start nginx
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Aguardar inicialização
sleep 5

echo "Parte 4 concluída: configuração do sistema finalizada."

# ==========================================
# FINALIZAÇÃO E INFORMAÇÕES
# ==========================================

echo "================================================================"
echo "                    ANSITRIX INSTALADO COM SUCESSO!"
echo "================================================================"
echo ""
echo "Informações de Acesso:"
echo "----------------------"
echo "URL de Acesso: http://$(hostname -I | awk '{print $1}')"
echo "Usuário: admin"
echo "Senha: ansitrix123"
echo ""
echo "IMPORTANTE: Altere a senha padrão após o primeiro login!"
echo ""
echo "Comandos úteis:"
echo "- Status do serviço: sudo systemctl status ansitrix"
echo "- Ver logs: sudo journalctl -u ansitrix -f"
echo "- Reiniciar: sudo systemctl restart ansitrix"
echo "- Backup manual: sudo /opt/ansitrix/backup.sh"
echo ""
echo "A ferramenta inclui comandos importantes pré-cadastrados para"
echo "gerenciamento de Mikrotiks via Ansible."
echo ""
echo "================================================================"

# Verificação final
if curl -s http://localhost >/dev/null 2>&1; then
    echo "✓ Ansitrix está funcionando corretamente!"
else
    echo "⚠ Verifique os logs se houver problemas de acesso."
    echo "Para debug: sudo journalctl -u ansitrix -f"
fi

echo ""
echo "Instalação finalizada em $(date)"
echo "================================================================"
