#!/bin/bash
set -euo pipefail

APP_DIR="/opt/grafeno_automate"
APP_USER="grafeno"
GUNICORN_BIND="127.0.0.1:8000"
SECRET_KEY="$(openssl rand -hex 32)"
ADMIN_PASS="$(openssl rand -base64 16 | tr -dc 'A-Za-z0-9@#%+=_' | head -c 16)"
LOG_FILE="$APP_DIR/install.log"

echo "Iniciando instalação do Grafeno Automate..."
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[1/10] Atualizando sistema..."
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y

echo "[2/10] Instalando dependências..."
apt install -y python3 python3-venv python3-pip python3-dev build-essential libffi-dev libssl-dev nginx git curl openssl

echo "[3/10] Criando usuário $APP_USER..."
if ! id "$APP_USER" &>/dev/null; then
  useradd -m -s /bin/bash "$APP_USER"
fi

echo "[4/10] Preparando diretórios..."
mkdir -p "$APP_DIR"/{templates,static/css,logs}
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

echo "[5/10] Criando ambiente virtual e instalando libs..."
sudo -u "$APP_USER" python3 -m venv "$APP_DIR/venv"
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install --upgrade pip
sudo -u "$APP_USER" "$APP_DIR/venv/bin/pip" install flask flask-login flask_sqlalchemy netmiko gunicorn bcrypt

echo "[6/10] Criando app.py..."
cat > "$APP_DIR/app.py" << EOF
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from netmiko import ConnectHandler
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '$SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grafeno_automate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Grupo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text)
    mikrotiks = db.relationship('Mikrotik', backref='grupo', lazy=True)

class Mikrotik(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    ip = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    grupo_id = db.Column(db.Integer, db.ForeignKey('grupo.id'))

class ComandoRapido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    command = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)

class LogExecucao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mikrotik_id = db.Column(db.Integer, db.ForeignKey('mikrotik.id'))
    comando_id = db.Column(db.Integer, db.ForeignKey('comando_rapido.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    output = db.Column(db.Text)
    status = db.Column(db.String(20))
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)

    mikrotik = db.relationship('Mikrotik')
    comando = db.relationship('ComandoRapido')
    user = db.relationship('User  ')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = User.query.filter_by(username=request.form['username']).first()
        if u and u.check_password(request.form['password']):
            login_user(u)
            return redirect(url_for('dashboard'))
        flash('Usuário ou senha inválidos', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    mikrotiks = Mikrotik.query.all()
    grupos = Grupo.query.all()
    comandos = ComandoRapido.query.all()
    logs = LogExecucao.query.order_by(LogExecucao.executed_at.desc()).limit(10).all()
    return render_template('dashboard.html', mikrotiks=mikrotiks, grupos=grupos, comandos=comandos, logs=logs)

@app.route('/mikrotik/add', methods=['GET', 'POST'])
@login_required
def add_mikrotik():
    if request.method == 'POST':
        m = Mikrotik(
            name=request.form['name'],
            ip=request.form['ip'],
            username=request.form['username'],
            password=request.form['password'],
            grupo_id=request.form.get('grupo_id') or None
        )
        db.session.add(m)
        db.session.commit()
        flash('Mikrotik adicionado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    grupos = Grupo.query.all()
    return render_template('add_mikrotik.html', grupos=grupos)

@app.route('/grupo/add', methods=['GET', 'POST'])
@login_required
def add_grupo():
    if request.method == 'POST':
        g = Grupo(name=request.form['name'], description=request.form.get('description'))
        db.session.add(g)
        db.session.commit()
        flash('Grupo criado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_grupo.html')

@app.route('/comando/add', methods=['GET', 'POST'])
@login_required
def add_comando():
    if request.method == 'POST':
        c = ComandoRapido(name=request.form['name'], command=request.form['command'], description=request.form.get('description'))
        db.session.add(c)
        db.session.commit()
        flash('Comando rápido adicionado!', 'success')
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
        'session_timeout': 60,
        'fast_cli': False,
        'global_delay_factor': 1.5
    }
    log_exec = LogExecucao(mikrotik_id=mikrotik.id, comando_id=comando.id, user_id=current_user.id)
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_command_timing(comando.command)
        if any(x in output.lower() for x in ['reboot', 'are you sure', '[y/n]']):
            output += "\\n" + net_connect.send_command_timing("y")
        net_connect.disconnect()
        log_exec.output = output
        log_exec.status = 'success'
        flash(f'Comando "{comando.name}" executado com sucesso!', 'success')
    except Exception as e:
        log_exec.output = str(e)
        log_exec.status = 'error'
        flash(f'Erro ao executar comando: {str(e)}', 'danger')
    db.session.add(log_exec)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/mikrotik/<int:mikrotik_id>/delete')
@login_required
def delete_mikrotik(mikrotik_id):
    m = Mikrotik.query.get_or_404(mikrotik_id)
    db.session.delete(m)
    db.session.commit()
    flash('Mikrotik removido com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/comando/<int:comando_id>/delete')
@login_required
def delete_comando(comando_id):
    c = ComandoRapido.query.get_or_404(comando_id)
    db.session.delete(c)
    db.session.commit()
    flash('Comando removido com sucesso!', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    if not os.path.exists('grafeno_automate.db'):
        with app.app_context():
            db.create_all()
            admin = User(username='grafeno')
            admin.set_password('$ADMIN_PASS')
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000)
EOF
echo "[7/10] Criando templates e CSS..."

mkdir -p "$APP_DIR/templates" "$APP_DIR/static/css"

# base.html
cat > "$APP_DIR/templates/base.html" << 'EOF'
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{% block title %}Grafeno Automate{% endblock %}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" />
<link rel="stylesheet" href="{{ url_for('static', filename='css/grafeno.css') }}" />
</head>
<body class="bg-dark text-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard') }}">Grafeno Automate</a>
    {% if current_user.is_authenticated %}
    <div class="d-flex">
      <span class="navbar-text me-3">Olá, {{ current_user.username }}</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">Sair</a>
    </div>
    {% endif %}
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ 'danger' if category == 'danger' or category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
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
echo "[7/10] Criando templates e CSS..."

mkdir -p "$APP_DIR/templates" "$APP_DIR/static/css"

# base.html
cat > "$APP_DIR/templates/base.html" << 'EOF'
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{% block title %}Grafeno Automate{% endblock %}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" />
<link rel="stylesheet" href="{{ url_for('static', filename='css/grafeno.css') }}" />
</head>
<body class="bg-dark text-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('dashboard') }}">Grafeno Automate</a>
    {% if current_user.is_authenticated %}
    <div class="d-flex">
      <span class="navbar-text me-3">Olá, {{ current_user.username }}</span>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light btn-sm">Sair</a>
    </div>
    {% endif %}
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ 'danger' if category == 'danger' or category == 'error' else 'success' }} alert-dismissible fade show" role="alert">
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

# login.html
cat > "$APP_DIR/templates/login.html" << 'EOF'
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-4">
    <h2 class="mb-4">Login</h2>
    <form method="POST">
      <div class="mb-3">
        <label for="username" class="form-label">Usuário</label>
        <input type="text" class="form-control" id="username" name="username" required autofocus />
      </div>
      <div class="mb-3">
        <label for="password" class="form-label">Senha</label>
        <input type="password" class="form-control" id="password" name="password" required />
      </div>
      <button type="submit" class="btn btn-primary w-100">Entrar</button>
    </form>
  </div>
</div>
{% endblock %}
EOF

# dashboard.html (abas separadas)
cat > "$APP_DIR/templates/dashboard.html" << 'EOF'
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<ul class="nav nav-tabs mb-3" id="tabs" role="tablist">
  <li class="nav-item" role="presentation">
    <button class="nav-link active" id="mikrotiks-tab" data-bs-toggle="tab" data-bs-target="#mikrotiks" type="button" role="tab" aria-controls="mikrotiks" aria-selected="true">Mikrotiks</button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="grupos-tab" data-bs-toggle="tab" data-bs-target="#grupos" type="button" role="tab" aria-controls="grupos" aria-selected="false">Grupos</button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="comandos-tab" data-bs-toggle="tab" data-bs-target="#comandos" type="button" role="tab" aria-controls="comandos" aria-selected="false">Comandos</button>
  </li>
  <li class="nav-item" role="presentation">
    <button class="nav-link" id="logs-tab" data-bs-toggle="tab" data-bs-target="#logs" type="button" role="tab" aria-controls="logs" aria-selected="false">Logs</button>
  </li>
</ul>
<div class="tab-content" id="tabsContent">
  <div class="tab-pane fade show active" id="mikrotiks" role="tabpanel" aria-labelledby="mikrotiks-tab">
    <a href="{{ url_for('add_mikrotik') }}" class="btn btn-success mb-3">Adicionar Mikrotik</a>
    {% if mikrotiks %}
      {% for m in mikrotiks %}
      <div class="d-flex justify-content-between align-items-center border-bottom py-2">
        <div>
          <strong>{{ m.name }}</strong><br>
          <small class="text-muted">{{ m.ip }}{% if m.grupo %} - {{ m.grupo.name }}{% endif %}</small>
        </div>
        <div>
          {% for c in comandos %}
            <a href="{{ url_for('executar', mikrotik_id=m.id, comando_id=c.id) }}" class="btn btn-outline-primary btn-sm me-1">{{ c.name }}</a>
          {% endfor %}
          <a href="{{ url_for('delete_mikrotik', mikrotik_id=m.id) }}" class="btn btn-outline-danger btn-sm" onclick="return confirm('Tem certeza?')">Remover</a>
        </div>
      </div>
      {% endfor %}
    {% else %}
      <p class="text-muted">Nenhum Mikrotik cadastrado</p>
    {% endif %}
  </div>
  <div class="tab-pane fade" id="grupos" role="tabpanel" aria-labelledby="grupos-tab">
    <a href="{{ url_for('add_grupo') }}" class="btn btn-success mb-3">Adicionar Grupo</a>
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
  <div class="tab-pane fade" id="comandos" role="tabpanel" aria-labelledby="comandos-tab">
    <a href="{{ url_for('add_comando') }}" class="btn btn-success mb-3">Adicionar Comando</a>
    {% if comandos %}
      {% for c in comandos %}
      <div class="d-flex justify-content-between align-items-center border-bottom py-2">
        <div>
          <strong>{{ c.name }}</strong><br>
          <small class="text-muted">{{ c.command[:50] }}{% if c.command|length > 50 %}...{% endif %}</small>
        </div>
        <a href="{{ url_for('delete_comando', comando_id=c.id) }}" class="btn btn-outline-danger btn-sm" onclick="return confirm('Tem certeza?')">Remover</a>
      </div>
      {% endfor %}
    {% else %}
      <p class="text-muted">Nenhum comando cadastrado</p>
    {% endif %}
  </div>
  <div class="tab-pane fade" id="logs" role="tabpanel" aria-labelledby="logs-tab">
    <h5>Últimos Logs</h5>
    {% if logs %}
      <table class="table table-dark table-striped">
        <thead>
          <tr><th>Data</th><th>Mikrotik</th><th>Comando</th><th>Status</th><th>Output</th></tr>
        </thead>
        <tbody>
          {% for log in logs %}
          <tr>
            <td>{{ log.executed_at.strftime('%d/%m/%Y %H:%M:%S') }}</td>
            <td>{{ log.mikrotik.name }}</td>
            <td>{{ log.comando.name }}</td>
            <td>
              {% if log.status == 'success' %}
                <span class="badge bg-success">Sucesso</span>
              {% else %}
                <span class="badge bg-danger">Erro</span>
              {% endif %}
            </td>
            <td><pre style="max-height:100px;overflow:auto;">{{ log.output }}</pre>
{% endblock %}
EOF

# add_mikrotik.html
cat > "$APP_DIR/templates/add_mikrotik.html" << 'EOF'
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

# add_grupo.html
cat > "$APP_DIR/templates/add_grupo.html" << 'EOF'
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

# add_comando.html
cat > "$APP_DIR/templates/add_comando.html" << 'EOF'
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
  </div>
</div>
{% endblock %}
EOF
echo "[8/10] Criando CSS..."
cat > "$APP_DIR/static/css/grafeno.css" << 'EOF'
body {
  background-color: #121212;
  color: #e0e0e0;
  font-family: "Fira Code", monospace, monospace;
}
a {
  color: #82aaff;
}
a:hover {
  color: #c792ea;
}
.navbar {
  background-color: #292d3e !important;
}
.table-dark {
  background-color: #1e1e2f;
}
.table-dark th, .table-dark td {
  border-color: #44475a;
}
.btn-primary {
  background-color: #6272a4;
  border-color: #6272a4;
}
.btn-primary:hover {
  background-color: #7083c6;
  border-color: #7083c6;
}
.btn-success {
  background-color: #50fa7b;
  border-color: #50fa7b;
  color: #000;
}
.btn-success:hover {
  background-color: #3adb5a;
  border-color: #3adb5a;
  color: #000;
}
.badge.bg-success {
  background-color: #50fa7b;
  color: #000;
}
.badge.bg-danger {
  background-color: #ff5555;
}
pre {
  background-color: #282a36;
  color: #f8f8f2;
  padding: 10px;
  border-radius: 5px;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-wrap: break-word;
}
EOF

echo "[9/10] Criando serviço systemd..."
cat > /etc/systemd/system/grafeno-automate.service << EOF
[Unit]
Description=Grafeno Automate - Sistema de Gerenciamento Mikrotik
After=network.target

[Service]
User =root
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
Environment="SECRET_KEY=$SECRET_KEY"
ExecStart=$APP_DIR/venv/bin/gunicorn -w 4 -b $GUNICORN_BIND app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "[10/10] Configurando Nginx..."
cat > /etc/nginx/sites-available/grafeno-automate << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://$GUNICORN_BIND;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static/ {
        alias $APP_DIR/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    access_log /var/log/nginx/grafeno-automate_access.log;
    error_log /var/log/nginx/grafeno-automate_error.log;
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/grafeno-automate /etc/nginx/sites-enabled/

nginx -t

echo "Inicializando banco de dados e criando usuário admin..."
cd "$APP_DIR"
sudo -u "$APP_USER" bash -c "
source venv/bin/activate
python3 -c '
from app import app, db, User
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username=\"grafeno\").first():
        admin = User(username=\"grafeno\")
        admin.set_password(\"$ADMIN_PASS\")
        db.session.add(admin)
        db.session.commit()
        print(\"Usuário admin criado com senha: $ADMIN_PASS\")
    else:
        print(\"Usuário admin já existe.\")
'
"

echo "Habilitando e iniciando serviços..."
systemctl daemon-reload
systemctl enable grafeno-automate
systemctl restart grafeno-automate
systemctl restart nginx

echo "Instalação concluída!"
echo "Acesse: http://$(hostname -I | awk '{print $1}')"
echo "Usuário: grafeno"
echo "Senha: $ADMIN_PASS"
echo "Salve essa senha, ela não será exibida novamente."

