#!/bin/bash

set -e

echo "=========================================="
echo "    GRAFENO AUTOMATE - INSTALAÇÃO"
echo "=========================================="

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

if [ "$EUID" -ne 0 ]; then
    error "Execute este script como root (sudo ./install_grafeno_automate.sh)"
fi

log "Atualizando sistema..."
apt update && apt upgrade -y

log "Instalando dependências básicas..."
apt install python3 python3-pip python3-venv nginx git curl openssl -y

if ! id "grafeno" &>/dev/null; then
    log "Criando usuário grafeno..."
    useradd -m -s /bin/bash grafeno
fi

APP_DIR="/opt/grafeno_automate"
log "Criando diretório da aplicação em $APP_DIR..."
mkdir -p $APP_DIR
cd $APP_DIR

SECRET_KEY=$(openssl rand -hex 32)
log "Chave secreta gerada"

ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
log "Senha do admin gerada: $ADMIN_PASSWORD"

log "Criando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

log "Criando requirements.txt..."
cat > requirements.txt << EOF
flask==2.3.3
flask-login==0.6.3
flask_sqlalchemy==3.0.5
netmiko==4.2.0
gunicorn==21.2.0
bcrypt==4.0.1
EOF

log "Instalando dependências Python..."
pip install --upgrade pip
pip install -r requirements.txt

log "Criando estrutura de diretórios..."
mkdir -p templates static/css logs

log "Criando aplicação principal..."
cat > app.py << EOF
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from netmiko import ConnectHandler
from datetime import datetime
import os
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '$SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///grafeno_automate.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logging.basicConfig(filename='logs/grafeno_automate.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

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
    user = db.relationship('User ')

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
            admin.set_password('$ADMIN_PASSWORD')
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=5000)
EOF

log "Criando templates e CSS..."

mkdir -p templates static/css

cat > templates/base.html << 'EOF'
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

cat > templates/login.html << 'EOF'
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

cat > templates/dashboard.html << 'EOF'
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
            <td><pre style="max-height:100px;overflow:auto;">{{ log.output }}</pre></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p class="text-muted">Nenhum log disponível.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
EOF

log "Criando CSS..."
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
    background-color: #121212;
    color: #e0e0e0;
    font-family: "Fira Code", monospace, monospace;
}

a {
    color: var(--grafeno-accent);
}
a:hover {
    color: #c792ea;
}

.navbar {
    background-color: var(--grafeno-secondary) !important;
}

.table-dark {
    background-color: #1e1e2f;
}
.table-dark th, .table-dark td {
    border-color: #44475a;
}

.btn-primary {
    background-color: var(--grafeno-primary);
    border-color: var(--grafeno-primary);
}
.btn-primary:hover {
    background-color: var(--grafeno-secondary);
    border-color: var(--grafeno-secondary);
}

.btn-success {
    background-color: var(--grafeno-success);
    border-color: var(--grafeno-success);
    color: #000;
}
.btn-success:hover {
    background-color: #3adb5a;
    border-color: #3adb5a;
    color: #000;
}

.badge.bg-success {
    background-color: var(--grafeno-success);
    color: #000;
}
.badge.bg-danger {
    background-color: var(--grafeno-danger);
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

log "Criando script de inicialização do banco..."
cat > init_db.py << EOF
#!/usr/bin/env python3
from app import app, db, User, ComandoRapido

def init_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='grafeno').first():
            admin = User(username='grafeno')
            admin.set_password('$ADMIN_PASSWORD')
            db.session.add(admin)
            comandos_padrao = [
                {'name': 'Reboot', 'command': '/system reboot', 'description': 'Reinicia o sistema Mikrotik'},
                {'name': 'Export Config', 'command': '/export file=backup_config', 'description': 'Exporta configuração'},
                {'name': 'Show Users', 'command': '/user print', 'description': 'Lista usuários'},
                {'name': 'Show Version', 'command': '/system resource print', 'description': 'Info do sistema'},
                {'name': 'Show IP Addresses', 'command': '/ip address print', 'description': 'Lista IPs'},
                {'name': 'Show Interfaces', 'command': '/interface print', 'description': 'Lista interfaces'},
                {'name': 'Show Routes', 'command': '/ip route print', 'description': 'Tabela de rotas'},
                {'name': 'Show DHCP Leases', 'command': '/ip dhcp-server lease print', 'description': 'Leases DHCP'}
            ]
            for cmd in comandos_padrao:
                db.session.add(ComandoRapido(**cmd))
            db.session.commit()
            print("✅ Banco de dados inicializado com sucesso!")
            print(f"👤 Usuário: grafeno")
            print(f"🔑 Senha: $ADMIN_PASSWORD")
        else:
            print("ℹ️ Banco de dados já inicializado")

if __name__ == '__main__':
    init_database()
EOF

log "Criando serviço systemd..."
cat > /etc/systemd/system/grafeno-automate.service << EOF
[Unit]
Description=Grafeno Automate - Sistema de Gerenciamento Mikrotik
After=network.target

[Service]
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
Environment="SECRET_KEY=$SECRET_KEY"
ExecStart=$APP_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

log "Configurando Nginx..."
cat > /etc/nginx/sites-available/grafeno-automate << EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
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

chown -R root:root $APP_DIR
chmod +x init_db.py

log "Inicializando banco de dados..."
cd $APP_DIR
source venv/bin/activate
python3 init_db.py

log "Habilitando e iniciando serviços..."
systemctl daemon-reload
systemctl enable grafeno-automate
systemctl restart grafeno-automate
systemctl restart nginx

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

if systemctl is-active --quiet ufw; then
    log "Configurando firewall..."
    ufw allow 80/tcp
    ufw allow 22/tcp
    ufw --force enable
fi

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
log "   systemctl restart grafeno-automate"
log "   journalctl -u grafeno-automate -f"
log "   systemctl status grafeno-automate"
log ""
log "⚠️  IMPORTANTE: Anote a senha acima, ela não será exibida novamente!"
log ""

echo "=========================================" > $APP_DIR/CREDENCIAIS.txt
echo "GRAFENO AUTOMATE - CREDENCIAIS DE ACESSO" >> $APP_DIR/CREDENCIAIS.txt
echo "=========================================" >> $APP_DIR/CREDENCIAIS.txt
echo "URL: http://$(hostname -I | awk '{print $1}')" >> $APP_DIR/CREDENCIAIS.txt
echo "Usuário: grafeno" >> $APP_DIR/CREDENCIAIS.txt
echo "Senha: $ADMIN_PASSWORD" >> $APP_DIR/CREDENCIAIS.txt
echo "Data da instalação: $(date)" >> $APP_DIR/CREDENCIAIS.txt
echo "=========================================" >> $APP_DIR/CREDENCIAIS.txt

log "💾 Credenciais salvas em: $APP_DIR/CREDENCIAIS.txt"
                
