from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g, send_file, abort)
from functools import wraps
from datetime import datetime
from collections import Counter
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO, StringIO
import sqlite3, os, csv

# ---------- Dependências opcionais (exportação) ----------
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
                                    Paragraph, Spacer)
    from reportlab.lib.styles import getSampleStyleSheet
    from xml.sax.saxutils import escape as xml_escape
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

app = Flask(__name__)
import os

# Lê a SECRET_KEY da variável de ambiente.
# Se não existir, gera uma temporária apenas para desenvolvimento local
# (assim o projeto não quebra se você esquecer de configurar).
app.secret_key = os.environ.get('SECRET_KEY')

if not app.secret_key:
    import secrets
    app.secret_key = secrets.token_hex(32)
    app.logger.warning(
        '⚠️  SECRET_KEY não configurada como variável de ambiente. '
        'Usando chave temporária. Em produção isso causará logout '
        'de todos os usuários a cada reinício!'
    )
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'qualidade.db')

# ---------- Constantes ----------
USUARIOS_SEED = {
    'operador':   {'senha': 'op123',  'perfil': 'Operador'},
    'supervisor': {'senha': 'sup123', 'perfil': 'Supervisor'},
    'gestor':     {'senha': 'ges123', 'perfil': 'Gestor'},
    'diretor':    {'senha': 'dir123', 'perfil': 'Diretor'},
}

PERFIS = ['Operador', 'Supervisor', 'Gestor', 'Diretor']

PERMISSOES = {
    'Operador':   {'cadastro'},
    'Supervisor': {'cadastro', 'busca', 'editar_registro', 'excluir_registro', 'exportar'},
    'Gestor':     {'cadastro', 'busca', 'dashboard', 'editar_registro',
                   'excluir_registro', 'exportar', 'usuarios', 'auditoria'},
    'Diretor':    {'cadastro', 'busca', 'dashboard', 'editar_registro',
                   'excluir_registro', 'exportar', 'usuarios', 'auditoria'},
}

SETORES = ['Enfermaria', 'UTI Adulto', 'UTI Neonatal', 'Centro Cirúrgico',
           'Pronto Socorro', 'Laboratório', 'Farmácia', 'Radiologia',
           'Administrativo', 'Higienização']

TIPOS = ['Evento Adverso', 'Incidente', 'Near Miss', 'Não Conformidade',
         'Reclamação', 'Falha de Processo', 'Infecção Relacionada à Assistência']

# ==================================================================
# BANCO DE DADOS
# ==================================================================
import os
import psycopg2
import psycopg2.extras

# Lê a URL do banco da variável de ambiente.
# Em produção (Render), será a URL do Neon.
# Localmente, se não existir, usa SQLite (opcional para testes).
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    if 'db' not in g:
        if DATABASE_URL:
            # Produção: PostgreSQL (Neon)
            conn = psycopg2.connect(DATABASE_URL, sslmode='require')
            conn.cursor_factory = psycopg2.extras.RealDictCursor
            g.db = conn
        else:
            # Desenvolvimento local: SQLite (fallback)
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db
  
@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    if not DATABASE_URL:
        # SQLite local (código original mantido para desenvolvimento)
        con = sqlite3.connect(DB_PATH)
        con.execute('''CREATE TABLE IF NOT EXISTS registros (... mesma coisa ...)''')
        con.execute('''CREATE TABLE IF NOT EXISTS usuarios (... mesma coisa ...)''')
        con.execute('''CREATE TABLE IF NOT EXISTS auditoria (... mesma coisa ...)''')
        con.commit()
        con.close()
        return

    # PostgreSQL (Neon)
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    cur = conn.cursor()

    cur.execute('''CREATE TABLE IF NOT EXISTS registros (
        id SERIAL PRIMARY KEY,
        data TEXT NOT NULL,
        setor TEXT NOT NULL,
        log TEXT,
        tipo TEXT NOT NULL,
        motivo TEXT NOT NULL,
        observacao TEXT,
        criado_por TEXT,
        criado_em TEXT,
        atualizado_por TEXT,
        atualizado_em TEXT
    )''')

    cur.execute('''CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        perfil TEXT NOT NULL,
        ativo INTEGER DEFAULT 1,
        criado_em TEXT
    )''')

    cur.execute('''CREATE TABLE IF NOT EXISTS auditoria (
        id SERIAL PRIMARY KEY,
        timestamp TEXT NOT NULL,
        usuario TEXT,
        perfil TEXT,
        acao TEXT NOT NULL,
        entidade TEXT,
        entidade_id INTEGER,
        detalhes TEXT,
        ip TEXT
    )''')

    # Seed de usuários (se a tabela estiver vazia)
    cur.execute("SELECT COUNT(*) FROM usuarios")
    if cur.fetchone()[0] == 0:
        now = datetime.now().isoformat(timespec='seconds')
        for username, info in USUARIOS_SEED.items():
            cur.execute(
                "INSERT INTO usuarios (username, senha_hash, perfil, ativo, criado_em) "
                "VALUES (%s,%s,%s,1,%s)",
                (username, generate_password_hash(info['senha']),
                 info['perfil'], now)
            )

    conn.commit()
    cur.close()
    conn.close()

# ==================================================================
# AUTENTICAÇÃO E PERMISSÕES
# ==================================================================
def autenticar(username, senha):
    row = get_db().execute(
        "SELECT * FROM usuarios WHERE username=%s AND ativo=1",
        (username,)
    ).fetchone()
    if row and check_password_hash(row['senha_hash'], senha):
        return row
    return None

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'usuario' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def requer_permissao(tela):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'usuario' not in session:
                return redirect(url_for('login'))
            perfil = session.get('perfil')
            if tela not in PERMISSOES.get(perfil, set()):
                log_audit('ACESSO_NEGADO', 'rota', None,
                          f'Tentativa de acesso à tela "{tela}"')
                flash(f'Acesso negado: perfil "{perfil}" não tem permissão '
                      f'para a tela "{tela}".', 'erro')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ==================================================================
# AUDITORIA
# ==================================================================
def log_audit(acao, entidade=None, entidade_id=None, detalhes=None,
              usuario=None, perfil=None):
    """Registra um evento de auditoria."""
    try:
        usuario = usuario if usuario is not None else session.get('usuario')
        perfil = perfil if perfil is not None else session.get('perfil')
        ip = request.remote_addr if request else None
        db = get_db()
        db.execute('''INSERT INTO auditoria
            (timestamp, usuario, perfil, acao, entidade, entidade_id, detalhes, ip)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
            (datetime.now().isoformat(timespec='seconds'),
             usuario, perfil, acao, entidade, entidade_id,
             (detalhes or '')[:500], ip))
        db.commit()
    except Exception as e:
        app.logger.warning(f'Falha ao registrar auditoria: {e}')

# ==================================================================
# CONTEXT PROCESSOR
# ==================================================================
@app.context_processor
def inject_globals():
    perfil = session.get('perfil')
    return {
        'permissoes': PERMISSOES.get(perfil, set()),
        'setores': SETORES,
        'tipos': TIPOS,
        'perfis_disponiveis': PERFIS,
    }

# ==================================================================
# ROTAS – RAIZ / LOGIN / LOGOUT
# ==================================================================
@app.route('/')
def index():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    permitidas = PERMISSOES.get(session.get('perfil'), set())
    for tela in ('dashboard', 'busca', 'cadastro'):
        if tela in permitidas:
            return redirect(url_for(tela))
    flash('Seu perfil não possui nenhuma tela habilitada.', 'erro')
    return redirect(url_for('logout'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip().lower()
        senha = request.form.get('senha', '')
        row = autenticar(usuario, senha)
        if row:
            session['usuario'] = row['username']
            session['perfil'] = row['perfil']
            session['usuario_id'] = row['id']
            log_audit('LOGIN_OK', 'usuario', row['id'], 'Login realizado')
            flash(f'Bem-vindo, {row["username"]} ({row["perfil"]})!', 'ok')
            return redirect(url_for('index'))
        log_audit('LOGIN_FALHA', 'usuario', None,
                  f'Tentativa com usuário "{usuario}"',
                  usuario=usuario, perfil='-')
        flash('Usuário ou senha inválidos, ou usuário inativo.', 'erro')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'usuario' in session:
        log_audit('LOGOUT', 'usuario', session.get('usuario_id'), 'Sessão encerrada')
    session.clear()
    flash('Sessão encerrada.', 'ok')
    return redirect(url_for('login'))

# ==================================================================
# ROTAS – CADASTRO
# ==================================================================
@app.route('/cadastro', methods=['GET', 'POST'])
@requer_permissao('cadastro')
def cadastro():
    if request.method == 'POST':
        data = request.form.get('data', '').strip()
        setor = request.form.get('setor', '').strip()
        log = request.form.get('log', '').strip()
        tipo = request.form.get('tipo', '').strip()
        motivo = request.form.get('motivo', '').strip()
        observacao = request.form.get('observacao', '').strip()

        if not (data and setor and tipo and motivo):
            flash('Preencha todos os campos obrigatórios (*).', 'erro')
            return redirect(url_for('cadastro'))

        db = get_db()
        cur = db.execute('''INSERT INTO registros
            (data, setor, log, tipo, motivo, observacao, criado_por, criado_em)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
            (data, setor, log, tipo, motivo, observacao,
             session['usuario'],
             datetime.now().isoformat(timespec='seconds')))
        db.commit()
        novo_id = cur.lastrowid
        log_audit('INSERIR_REGISTRO', 'registro', novo_id,
                  f'Data={data}; Setor={setor}; Tipo={tipo}; LOG={log}')
        flash('Registro cadastrado com sucesso!', 'ok')
        return redirect(url_for('cadastro'))
    return render_template('cadastro.html')

# ==================================================================
# ROTAS – BUSCA
# ==================================================================
def _buscar_registros():
    """Aplica os filtros do querystring e devolve as linhas."""
    f = {
        'data_ini': request.args.get('data_ini', '').strip(),
        'data_fim': request.args.get('data_fim', '').strip(),
        'setor':    request.args.get('setor', '').strip(),
        'tipo':     request.args.get('tipo', '').strip(),
        'log':      request.args.get('log', '').strip(),
        'motivo':   request.args.get('motivo', '').strip(),
    }
    sql = "SELECT * FROM registros WHERE 1=1"
    params = []
    if f['data_ini']:
        sql += " AND data >= %s"; params.append(f['data_ini'])
    if f['data_fim']:
        sql += " AND data <= %s"; params.append(f['data_fim'])
    if f['setor']:
        sql += " AND setor = %s"; params.append(f['setor'])
    if f['tipo']:
        sql += " AND tipo = %s"; params.append(f['tipo'])
    if f['log']:
        sql += " AND log LIKE %s"; params.append(f'%{f["log"]}%')
    if f['motivo']:
        sql += " AND motivo LIKE %s"; params.append(f'%{f["motivo"]}%')
    sql += " ORDER BY data DESC, id DESC"
    return get_db().execute(sql, params).fetchall(), f

@app.route('/busca')
@requer_permissao('busca')
def busca():
    registros, filtros = _buscar_registros()
    return render_template('busca.html', registros=registros, filtros=filtros)

# --------- Editar ---------
@app.route('/registro/<int:rid>/editar', methods=['GET', 'POST'])
@requer_permissao('editar_registro')
def registro_editar(rid):
    db = get_db()
    r = db.execute("SELECT * FROM registros WHERE id=%s", (rid,)).fetchone()
    if not r:
        flash('Registro não encontrado.', 'erro')
        return redirect(url_for('busca'))

    if request.method == 'POST':
        data = request.form.get('data', '').strip()
        setor = request.form.get('setor', '').strip()
        log = request.form.get('log', '').strip()
        tipo = request.form.get('tipo', '').strip()
        motivo = request.form.get('motivo', '').strip()
        observacao = request.form.get('observacao', '').strip()

        if not (data and setor and tipo and motivo):
            flash('Preencha todos os campos obrigatórios (*).', 'erro')
            return redirect(url_for('registro_editar', rid=rid))

        db.execute('''UPDATE registros SET
            data=%s, setor=%s, log=%s, tipo=%s, motivo=%s, observacao=%s,
            atualizado_por=%s, atualizado_em=%s
            WHERE id=%s''',
            (data, setor, log, tipo, motivo, observacao,
             session['usuario'],
             datetime.now().isoformat(timespec='seconds'),
             rid))
        db.commit()
        log_audit('ATUALIZAR_REGISTRO', 'registro', rid,
                  f'Data={data}; Setor={setor}; Tipo={tipo}')
        flash('Registro atualizado com sucesso!', 'ok')
        return redirect(url_for('busca'))

    return render_template('registro_editar.html', r=r)

# --------- Excluir ---------
@app.route('/registro/<int:rid>/excluir', methods=['POST'])
@requer_permissao('excluir_registro')
def registro_excluir(rid):
    db = get_db()
    r = db.execute("SELECT * FROM registros WHERE id=%s", (rid,)).fetchone()
    if not r:
        flash('Registro não encontrado.', 'erro')
        return redirect(url_for('busca'))
    db.execute("DELETE FROM registros WHERE id=%s", (rid,))
    db.commit()
    log_audit('EXCLUIR_REGISTRO', 'registro', rid,
              f'Data={r["data"]}; Setor={r["setor"]}; Tipo={r["tipo"]}')
    flash('Registro excluído com sucesso.', 'ok')
    return redirect(url_for('busca'))

# ==================================================================
# ROTAS – EXPORTAÇÃO
# ==================================================================
def _nome_arquivo(ext):
    return f'registros_{datetime.now():%Y%m%d_%H%M%S}.{ext}'

@app.route('/exportar/csv')
@requer_permissao('exportar')
def exportar_csv():
    registros, _ = _buscar_registros()
    buf = StringIO()
    buf.write('\ufeff')  # BOM para Excel abrir com acentos
    w = csv.writer(buf, delimiter=';')
    w.writerow(['ID','Data','Setor','LOG','Tipo','Motivo','Observação',
                'Criado por','Criado em','Atualizado por','Atualizado em'])
    for r in registros:
        w.writerow([r['id'], r['data'], r['setor'], r['log'] or '',
                    r['tipo'], r['motivo'], r['observacao'] or '',
                    r['criado_por'] or '', r['criado_em'] or '',
                    r['atualizado_por'] or '', r['atualizado_em'] or ''])
    bio = BytesIO(buf.getvalue().encode('utf-8'))
    log_audit('EXPORTAR_CSV', 'registros', None, f'{len(registros)} registros')
    return send_file(bio, as_attachment=True, download_name=_nome_arquivo('csv'),
                     mimetype='text/csv')

@app.route('/exportar/excel')
@requer_permissao('exportar')
def exportar_excel():
    if not HAS_OPENPYXL:
        flash('Biblioteca "openpyxl" não instalada. '
              'Execute: pip install openpyxl', 'erro')
        return redirect(url_for('busca'))

    registros, _ = _buscar_registros()
    wb = Workbook()
    ws = wb.active
    ws.title = 'Registros'

    headers = ['ID','Data','Setor','LOG','Tipo','Motivo','Observação',
               'Criado por','Criado em','Atualizado por','Atualizado em']
    ws.append(headers)

    head_font = Font(bold=True, color='FFFFFF')
    head_fill = PatternFill('solid', fgColor='0F766E')
    for cell in ws[1]:
        cell.font = head_font
        cell.fill = head_fill
        cell.alignment = Alignment(horizontal='center', vertical='center')

    for r in registros:
        ws.append([r['id'], r['data'], r['setor'], r['log'] or '',
                   r['tipo'], r['motivo'], r['observacao'] or '',
                   r['criado_por'] or '', r['criado_em'] or '',
                   r['atualizado_por'] or '', r['atualizado_em'] or ''])

    widths = [6, 12, 16, 14, 26, 40, 30, 14, 20, 14, 20]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[chr(64 + i)].width = w

    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)
    log_audit('EXPORTAR_EXCEL', 'registros', None, f'{len(registros)} registros')
    return send_file(bio, as_attachment=True,
                     download_name=_nome_arquivo('xlsx'),
                     mimetype='application/vnd.openxmlformats-officedocument'
                              '.spreadsheetml.sheet')

@app.route('/exportar/pdf')
@requer_permissao('exportar')
def exportar_pdf():
    if not HAS_REPORTLAB:
        flash('Biblioteca "reportlab" não instalada. '
              'Execute: pip install reportlab', 'erro')
        return redirect(url_for('busca'))

    registros, _ = _buscar_registros()
    bio = BytesIO()
    doc = SimpleDocTemplate(bio, pagesize=landscape(A4),
                            leftMargin=20, rightMargin=20,
                            topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    h_txt = f'Relatório de Ocorrências – Gestão da Qualidade ONA 3'
    sub = (f'Gerado em {datetime.now():%d/%m/%Y %H:%M} '
           f'por {session.get("usuario")} · Total: {len(registros)} registros')

    def P(t, s):
        return Paragraph(xml_escape(str(t or '')), s)

    elements = [
        Paragraph(h_txt, styles['Title']),
        Paragraph(sub, styles['Normal']),
        Spacer(1, 12),
    ]

    data = [['Data','Setor','LOG','Tipo','Motivo','Observação','Criado por']]
    for r in registros:
        data.append([
            P(r['data'], styles['Normal']),
            P(r['setor'], styles['Normal']),
            P(r['log'], styles['Normal']),
            P(r['tipo'], styles['Normal']),
            P((r['motivo'] or '')[:120], styles['Normal']),
            P((r['observacao'] or '')[:120], styles['Normal']),
            P(r['criado_por'], styles['Normal']),
        ])

    t = Table(data, repeatRows=1, colWidths=[60, 80, 70, 100, 180, 150, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), rl_colors.HexColor('#0f766e')),
        ('TEXTCOLOR', (0,0), (-1,0), rl_colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.25, rl_colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [rl_colors.white, rl_colors.HexColor('#f0fdfa')]),
    ]))
    elements.append(t)
    doc.build(elements)
    bio.seek(0)

    log_audit('EXPORTAR_PDF', 'registros', None, f'{len(registros)} registros')
    return send_file(bio, as_attachment=True,
                     download_name=_nome_arquivo('pdf'),
                     mimetype='application/pdf')

# ==================================================================
# ROTAS – DASHBOARD
# ==================================================================
@app.route('/dashboard')
@requer_permissao('dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/dashboard')
@requer_permissao('dashboard')
def api_dashboard():
    data_ini = request.args.get('data_ini', '').strip()
    data_fim = request.args.get('data_fim', '').strip()

    sql = "SELECT data, setor, log, tipo FROM registros WHERE 1=1"
    params = []
    if data_ini:
        sql += " AND data >= %s"; params.append(data_ini)
    if data_fim:
        sql += " AND data <= %s"; params.append(data_fim)
    rows = get_db().execute(sql, params).fetchall()

    por_setor = Counter(r['setor'] for r in rows)
    por_tipo  = Counter(r['tipo'] for r in rows)
    por_log   = Counter((r['log'] or 'Sem LOG') for r in rows)

    por_mes = Counter()
    for r in rows:
        try:
            d = datetime.strptime(r['data'], '%Y-%m-%d')
            por_mes[d.strftime('%Y-%m')] += 1
        except Exception:
            pass

    return jsonify({
        'total': len(rows),
        'por_setor': dict(por_setor.most_common()),
        'por_tipo':  dict(por_tipo.most_common()),
        'por_log':   dict(por_log.most_common()),
        'por_mes':   dict(sorted(por_mes.items())),
        'periodo': {'data_ini': data_ini, 'data_fim': data_fim},
    })

# ==================================================================
# ROTAS – USUÁRIOS (Gestor / Diretor)
# ==================================================================
@app.route('/usuarios')
@requer_permissao('usuarios')
def usuarios_lista():
    rows = get_db().execute(
        "SELECT * FROM usuarios ORDER BY username"
    ).fetchall()
    return render_template('usuarios.html', usuarios=rows)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@requer_permissao('usuarios')
def usuario_novo():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        senha = request.form.get('senha', '')
        perfil = request.form.get('perfil', '').strip()

        if not (username and senha and perfil in PERFIS):
            flash('Preencha todos os campos corretamente.', 'erro')
            return redirect(url_for('usuario_novo'))
        if len(senha) < 4:
            flash('A senha deve ter pelo menos 4 caracteres.', 'erro')
            return redirect(url_for('usuario_novo'))

        db = get_db()
        try:
            cur = db.execute('''INSERT INTO usuarios
                (username, senha_hash, perfil, ativo, criado_em)
                VALUES (%s,%s,%s,1,%s)''',
                (username, generate_password_hash(senha), perfil,
                 datetime.now().isoformat(timespec='seconds')))
            db.commit()
            log_audit('CRIAR_USUARIO', 'usuario', cur.lastrowid,
                      f'username={username}; perfil={perfil}')
            flash(f'Usuário "{username}" criado com sucesso.', 'ok')
            return redirect(url_for('usuarios_lista'))
        except sqlite3.IntegrityError:
            flash(f'O usuário "{username}" já existe.', 'erro')
            return redirect(url_for('usuario_novo'))

    return render_template('usuario_form.html', modo='novo', u=None)

@app.route('/usuarios/<int:uid>/editar', methods=['GET', 'POST'])
@requer_permissao('usuarios')
def usuario_editar(uid):
    db = get_db()
    u = db.execute("SELECT * FROM usuarios WHERE id=%s", (uid,)).fetchone()
    if not u:
        flash('Usuário não encontrado.', 'erro')
        return redirect(url_for('usuarios_lista'))

    if request.method == 'POST':
        perfil = request.form.get('perfil', '').strip()
        nova_senha = request.form.get('senha', '')
        ativo = 1 if request.form.get('ativo') else 0

        if perfil not in PERFIS:
            flash('Perfil inválido.', 'erro')
            return redirect(url_for('usuario_editar', uid=uid))

        # Não permitir que o próprio usuário se desative
        if uid == session.get('usuario_id') and ativo == 0:
            flash('Você não pode desativar o próprio usuário.', 'erro')
            return redirect(url_for('usuario_editar', uid=uid))

        if nova_senha:
            if len(nova_senha) < 4:
                flash('A nova senha deve ter pelo menos 4 caracteres.', 'erro')
                return redirect(url_for('usuario_editar', uid=uid))
            db.execute("UPDATE usuarios SET perfil=%s, ativo=%s, senha_hash=%s WHERE id=%s",
                       (perfil, ativo, generate_password_hash(nova_senha), uid))
            detalhes = f'perfil={perfil}; ativo={ativo}; senha=alterada'
        else:
            db.execute("UPDATE usuarios SET perfil=%s, ativo=%s WHERE id=%s",
                       (perfil, ativo, uid))
            detalhes = f'perfil={perfil}; ativo={ativo}'
        db.commit()

        # Se estiver editando o próprio perfil, atualizar a sessão
        if uid == session.get('usuario_id'):
            session['perfil'] = perfil

        log_audit('ATUALIZAR_USUARIO', 'usuario', uid, detalhes)
        flash('Usuário atualizado com sucesso.', 'ok')
        return redirect(url_for('usuarios_lista'))

    return render_template('usuario_form.html', modo='editar', u=u)

@app.route('/usuarios/<int:uid>/toggle', methods=['POST'])
@requer_permissao('usuarios')
def usuario_toggle(uid):
    if uid == session.get('usuario_id'):
        flash('Você não pode ativar/desativar o próprio usuário.', 'erro')
        return redirect(url_for('usuarios_lista'))
    db = get_db()
    u = db.execute("SELECT * FROM usuarios WHERE id=%s", (uid,)).fetchone()
    if not u:
        flash('Usuário não encontrado.', 'erro')
        return redirect(url_for('usuarios_lista'))
    novo = 0 if u['ativo'] else 1
    db.execute("UPDATE usuarios SET ativo=%s WHERE id=%s", (novo, uid))
    db.commit()
    log_audit('ALTERAR_STATUS_USUARIO', 'usuario', uid,
              f'username={u["username"]}; ativo={novo}')
    flash(f'Usuário {"ativado" if novo else "desativado"} com sucesso.', 'ok')
    return redirect(url_for('usuarios_lista'))

# ==================================================================
# ROTAS – AUDITORIA (Gestor / Diretor)
# ==================================================================
@app.route('/auditoria')
@requer_permissao('auditoria')
def auditoria_lista():
    f = {
        'usuario':  request.args.get('usuario', '').strip(),
        'acao':     request.args.get('acao', '').strip(),
        'data_ini': request.args.get('data_ini', '').strip(),
        'data_fim': request.args.get('data_fim', '').strip(),
    }
    sql = "SELECT * FROM auditoria WHERE 1=1"
    params = []
    if f['usuario']:
        sql += " AND usuario LIKE %s"; params.append(f'%{f["usuario"]}%')
    if f['acao']:
        sql += " AND acao = %s"; params.append(f['acao'])
    if f['data_ini']:
        sql += " AND substr(timestamp,1,10) >= %s"; params.append(f['data_ini'])
    if f['data_fim']:
        sql += " AND substr(timestamp,1,10) <= %s"; params.append(f['data_fim'])
    sql += " ORDER BY id DESC LIMIT 1000"

    rows = get_db().execute(sql, params).fetchall()
    acoes = [r[0] for r in get_db().execute(
        "SELECT DISTINCT acao FROM auditoria ORDER BY acao"
    ).fetchall()]
    return render_template('auditoria.html', logs=rows, filtros=f, acoes=acoes)

# ==================================================================
# INICIALIZAÇÃO
# ==================================================================
init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
