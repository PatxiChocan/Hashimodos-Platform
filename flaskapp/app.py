# app.py completo

# --- IMPORTS GENERALES ---
import requests
import base64
import json
import enum
import os
import ipaddress
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask,
    redirect,
    url_for,
    session,
    request,
    render_template,
    flash,
    jsonify,
    make_response,
    send_from_directory,
)
from authlib.integrations.flask_client import OAuth
from functools import wraps
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# --- MYSQL / SQLALCHEMY ---
import pymysql

pymysql.install_as_MySQLdb()
from flask_sqlalchemy import SQLAlchemy  # noqa: E402

# --- CLIENTE BANCO / API TARJETAS ---
from bank_client import bank_activate, bank_deactivate, bank_pay, bank_get_cards_info

# --- DESCARGA PDF --- #
from weasyprint import HTML

from json_scan_loader import load_scan_from_json


# ---------------------------------------------------------
# CONFIGURACIÓN FLASK
# ---------------------------------------------------------
app = Flask(__name__)
# Para que detecte correctamente HTTPS detrás de Nginx
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-key")
# --- SEGURIDAD COOKIES DE SESIÓN ---
app.config["SESSION_COOKIE_SECURE"] = True      # Solo por HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True    # No accesible desde JS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # Evita CSRF básicos manteniendo SSO

# --- CONFIGURACIÓN MYSQL ---
db_password = os.environ.get("DB_PASSWORD", "MkDehPass123")
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://mkdeh:{db_password}@localhost/mkdeh_cards"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Carpeta donde se guardarán los tickets de los gastos
app.config["UPLOAD_FOLDER"] = os.path.join(
    os.path.dirname(__file__), "static", "tickets"
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB máx por ticket
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


# ---------------------------------------------------------
# MODELOS BD
# ---------------------------------------------------------

class CardType(enum.Enum):
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class CardStatus(enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class Company(db.Model):
    __tablename__ = "companies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    # Nuevos campos según especificaciones
    cif = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones
    cards = db.relationship("Card", backref="company", lazy=True)
    transactions = db.relationship("Transaction", backref="company", lazy=True)
    expenses = db.relationship("Expense", backref="company", lazy=True)


class Card(db.Model):
    __tablename__ = "cards"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)

    type = db.Column(db.Enum(CardType), nullable=False)
    number = db.Column(db.String(64), nullable=False)
    status = db.Column(db.Enum(CardStatus), nullable=False, default=CardStatus.INACTIVE)
    balance = db.Column(db.Float, default=0.0)


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)
    card_id = db.Column(db.Integer, db.ForeignKey("cards.id"), nullable=False)

    # Nuevo: usuario que registró el pago
    user_id = db.Column(db.Integer, db.ForeignKey("user_profiles.id"), nullable=True)

    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    card = db.relationship("Card")
    user = db.relationship("UserProfile")   # para poder acceder como tx.user



class UserProfile(db.Model):
    __tablename__ = "user_profiles"

    id = db.Column(db.Integer, primary_key=True)
    keycloak_sub = db.Column(db.String(64), unique=True, nullable=False)
    username = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120))
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"))

    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    company = db.relationship("Company")


class Expense(db.Model):
    __tablename__ = "expenses"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)

    # Nuevo: usuario que registró el gasto
    user_id = db.Column(db.Integer, db.ForeignKey("user_profiles.id"), nullable=True)

    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    ticket_filename = db.Column(db.String(255))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relación para poder acceder como gasto.user
    user = db.relationship("UserProfile")



# ----------------------
# MODELO PARA ANÁLISIS RASPBERRY PI
# ----------------------
class ScanResult(db.Model):
    __tablename__ = "scan_results"

    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)

    open_ports_json = db.Column(db.Text, nullable=True)
    vulnerabilities_json = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    company = db.relationship("Company")

    @property
    def open_ports(self):
        if not self.open_ports_json:
            return []
        try:
            return json.loads(self.open_ports_json)
        except:
            return []

    @open_ports.setter
    def open_ports(self, value):
        self.open_ports_json = json.dumps(value or [])

    @property
    def vulnerabilities(self):
        if not self.vulnerabilities_json:
            return []
        try:
            return json.loads(self.vulnerabilities_json)
        except:
            return []

    @vulnerabilities.setter
    def vulnerabilities(self, value):
        self.vulnerabilities_json = json.dumps(value or [])

# ---------------------------------------------------------
# VALIDACIÓN DE IPs
#----------------------------------------------------------
import ipaddress
from flask import flash, redirect, url_for

def validate_scan_range(start_ip_str, end_ip_str):
    try:
        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)
    except ValueError:
        raise ValueError("Formato de IP no válido")

    # Último octeto
    start_last = int(str(start_ip).split(".")[3])
    end_last = int(str(end_ip).split(".")[3])

    # Restricción que tú quieres:
    #   - IP inicio: último octeto >= 1
    #   - IP fin: último octeto <= 255
    if start_last < 1:
        raise ValueError("La IP de inicio debe tener el último octeto mayor o igual que 1.")
    if end_last > 255:
        raise ValueError("La IP de fin debe tener el último octeto menor o igual que 255.")

    # Además comprobamos que la inicial no sea mayor que la final
    if start_ip > end_ip:
        raise ValueError("La IP de inicio no puede ser mayor que la IP de fin.")

    return str(start_ip), str(end_ip)

# ---------------------------------------------------------
# CAMBIO A HORA LOCAL EUROPA
# ---------------------------------------------------------

from datetime import datetime, date
from zoneinfo import ZoneInfo

TZ_LOCAL = ZoneInfo("Europe/Madrid")
TZ_UTC = ZoneInfo("UTC")

@app.template_filter("localtime")
def localtime(value, fmt="%d/%m/%Y %H:%M:%S"):
    if value is None:
        return ""

    # Si es solo date -> no hay zona horaria, se formatea y ya
    if isinstance(value, date) and not isinstance(value, datetime):
        return value.strftime(fmt)

    if not isinstance(value, datetime):
        return str(value)

    # Si viene sin tzinfo, asumimos que está en UTC
    if value.tzinfo is None:
        value = value.replace(tzinfo=TZ_UTC)

    value_local = value.astimezone(TZ_LOCAL)
    return value_local.strftime(fmt)


# ---------------------------------------------------------
# CONFIGURACIÓN KEYCLOAK
# ---------------------------------------------------------
KEYCLOAK_BASE_URL = "http://10.11.0.22:8080"
REALM = "Hashimodos"

CLIENT_ID = "flaskapp"
CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "dev-client-secret")

ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{REALM}"

oauth = OAuth(app)

keycloak = oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)


# ---------------------------------------------------------
# API KEY PARA RASPBERRY PI
# ---------------------------------------------------------
RASPBERRY_API_KEY = os.environ.get("RASPBERRY_API_KEY", "dev-raspberry-key")

RASPBERRY_BASE_URL = "http://10.11.0.171:5000"
# ---------------------------------------------------------
# AUTENTICACIÓN + ROLES
# ---------------------------------------------------------
def get_roles_from_token(token):
    """Extrae roles del access_token de Keycloak."""
    access_token = token.get("access_token")
    if not access_token:
        return []

    parts = access_token.split(".")
    if len(parts) != 3:
        return []

    payload = parts[1] + "=" * (-len(parts[1]) % 4)

    try:
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
    except:
        return []

    roles = set()
    roles.update(data.get("realm_access", {}).get("roles", []))

    for client_data in data.get("resource_access", {}).values():
        roles.update(client_data.get("roles", []))

    return list(roles)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Debe iniciar sesión.", "warning")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                flash("Debe iniciar sesión.", "warning")
                return redirect(url_for("index"))

            if role not in session.get("roles", []):
                return render_template("403.html", title="Acceso denegado"), 403

            return f(*args, **kwargs)
        return decorated
    return wrapper


def roles_required(*allowed_roles):
    """Permite acceso si el usuario tiene ≥1 rol permitido."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user" not in session:
                flash("Debe iniciar sesión.", "warning")
                return redirect(url_for("index"))

            user_roles = session.get("roles", [])
            if not any(r in user_roles for r in allowed_roles):
                return render_template("403.html", title="Acceso denegado"), 403

            return f(*args, **kwargs)
        return decorated
    return wrapper


# ---------------------------------------------------------
# LÓGICA DE NEGOCIO: TARJETAS / PAGOS
# ---------------------------------------------------------
def activate_card(company_id: int, card_type: CardType):
    company = Company.query.get(company_id)
    if not company:
        raise ValueError("Empresa no encontrada")

    debit = next((c for c in company.cards if c.type == CardType.DEBIT), None)
    credit = next((c for c in company.cards if c.type == CardType.CREDIT), None)

    if not debit or not credit:
        raise ValueError("La empresa no tiene ambas tarjetas")

    target = debit if card_type == CardType.DEBIT else credit
    other = credit if card_type == CardType.DEBIT else debit

    target.status = CardStatus.ACTIVE
    other.status = CardStatus.INACTIVE

    bank_activate(target.number)
    bank_deactivate(other.number)

    db.session.commit()


def process_payment(company_id: int, amount: float, description: str = "", user_profile: UserProfile | None = None):
    company = Company.query.get(company_id)
    if not company:
        raise ValueError("Empresa no encontrada")

    debit = next((c for c in company.cards if c.type == CardType.DEBIT), None)
    credit = next((c for c in company.cards if c.type == CardType.CREDIT), None)

    if not debit or not credit:
        raise ValueError("La empresa no tiene las dos tarjetas")

    active_card = next((c for c in company.cards if c.status == CardStatus.ACTIVE), None)
    if not active_card:
        raise ValueError("No hay tarjeta activa")

    if active_card.type == CardType.DEBIT and amount >= 500:
        raise ValueError("La tarjeta de débito no permite pagos ≥ 500 €.")

    bank_pay(active_card.number, amount, description)

    tx = Transaction(
        company_id=company_id,
        card_id=active_card.id,
        amount=amount,
        description=description,
        user_id=user_profile.id if user_profile else None,
    )

    db.session.add(tx)
    db.session.commit()
    return tx



# ---------------------------------------------------------
# RUTAS PRINCIPALES
# ---------------------------------------------------------
@app.route("/")
def index():
    if "user" not in session:
        return render_template("login.html", title="Iniciar sesión")

    roles = session.get("roles", [])
    current_company_id = session.get("current_company_id")
    company = None
    last_transactions = []
    last_gastos = []
    last_scan = None
    active_card = None

    if current_company_id:
        company = Company.query.get(current_company_id)

    # Si no hay empresa en sesión, usar perfil
    if not company:
        userinfo = session.get("user", {})
        sub = userinfo.get("sub")
        if sub:
            profile = UserProfile.query.filter_by(keycloak_sub=sub).first()
            if profile and profile.company_id:
                company = Company.query.get(profile.company_id)
                session["current_company_id"] = profile.company_id

    if company:
        last_transactions = (
            Transaction.query.filter_by(company_id=company.id)
            .order_by(Transaction.created_at.desc())
            .limit(5)
            .all()
        )
        last_gastos = (
            Expense.query.filter_by(company_id=company.id)
            .order_by(Expense.date.desc())
            .limit(5)
            .all()
        )
        last_scan = (
            ScanResult.query.filter_by(company_id=company.id)
            .order_by(ScanResult.created_at.desc())
            .first()
        )
        active_card = (
            Card.query.filter_by(company_id=company.id, status=CardStatus.ACTIVE)
            .first()
        )

    return render_template(
        "dashboard.html",
        title="Panel Principal",
        company=company,
        roles=roles,
        active_card=active_card,
        last_transactions=last_transactions,
        last_gastos=last_gastos,
        last_scan=last_scan,
    )


@app.route("/login")
def login():
    return keycloak.authorize_redirect(url_for("auth_callback", _external=True))


@app.route("/auth/callback")
def auth_callback():
    token = keycloak.authorize_access_token()
    userinfo = keycloak.userinfo()

    session["user"] = userinfo
    session["token"] = token
    session["roles"] = get_roles_from_token(token)

    sub = userinfo.get("sub")
    username = (
        userinfo.get("preferred_username")
        or userinfo.get("name")
        or userinfo.get("email")
    )
    email = userinfo.get("email")

    profile = UserProfile.query.filter_by(keycloak_sub=sub).first()
    if not profile:
        demo_company = Company.query.filter_by(name="Empresa Demo").first()
        profile = UserProfile(
            keycloak_sub=sub,
            username=username,
            email=email,
            company=demo_company,
        )
        db.session.add(profile)

    profile.username = username
    profile.email = email
    profile.last_login = datetime.utcnow()
    db.session.commit()

    if profile.company_id:
        session["current_company_id"] = profile.company_id

    flash("Sesión iniciada correctamente.", "success")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    redirect_url = url_for("index", _external=True)

    logout_url = (
        f"{KEYCLOAK_BASE_URL}/realms/{REALM}/protocol/openid-connect/logout"
        f"?client_id={CLIENT_ID}"
        f"&post_logout_redirect_uri={redirect_url}"
    )
    return redirect(logout_url)

# ---------------------------------------------------------
# PERFIL DE USUARIO
# ---------------------------------------------------------

@app.route("/perfil")
@login_required
def perfil():
    userinfo = session.get("user", {})
    roles = session.get("roles", [])

    sub = userinfo.get("sub")
    profile = None
    company = None

    if sub:
        profile = UserProfile.query.filter_by(keycloak_sub=sub).first()
        if profile and profile.company_id:
            company = Company.query.get(profile.company_id)

    return render_template(
        "perfil.html",
        title="Mi perfil",
        userinfo=userinfo,
        profile=profile,
        company=company,
        roles=roles,
    )


# ---------------------------------------------------------
# DEMO / EMPRESA
# ---------------------------------------------------------

@app.route("/init_demo")
@login_required
@role_required("admin")
def init_demo():
    existing = Company.query.filter_by(name="Empresa Demo").first()
    if existing:
        flash("La empresa demo ya existe.", "info")
        return redirect(url_for("ver_tarjetas", company_id=existing.id))

    c = Company(
        name="Empresa Demo",
        cif="B12345678",
        email="demo@mkdeh.local",
    )
    db.session.add(c)
    db.session.commit()

    db.session.add(Card(
        company_id=c.id,
        type=CardType.DEBIT,
        number="DEMO-DEBIT-0001",
        status=CardStatus.ACTIVE,
    ))
    db.session.add(Card(
        company_id=c.id,
        type=CardType.CREDIT,
        number="DEMO-CREDIT-0001",
        status=CardStatus.INACTIVE,
    ))
    db.session.commit()

    flash("Empresa demo creada correctamente.", "success")
    return redirect(url_for("ver_tarjetas", company_id=c.id))

# ---------------------------------------------------------
# TARJETAS
# ---------------------------------------------------------

@app.route("/empresa/<int:company_id>/tarjetas")
@login_required
@role_required("admin")
def ver_tarjetas(company_id):
    company = Company.query.get_or_404(company_id)

    # Info local
    debit = next((c for c in company.cards if c.type == CardType.DEBIT), None)
    credit = next((c for c in company.cards if c.type == CardType.CREDIT), None)

    current_card_number = "—"
    if debit and debit.status == CardStatus.ACTIVE:
        current_card_number = debit.number
    elif credit and credit.status == CardStatus.ACTIVE:
        current_card_number = credit.number

    bank_info = {
        "current_card": current_card_number,
        "card_debit": debit.number if debit else "—",
        "card_credit": credit.number if credit else "—",
        "raw": None,
    }

    # API Banco
    try:
        api_data = bank_get_cards_info()
        if isinstance(api_data, dict):
            for k in ["current_card", "card_debit", "card_credit"]:
                if api_data.get(k):
                    bank_info[k] = api_data[k]
            bank_info["raw"] = api_data
    except Exception as e:
        flash(f"No se ha podido obtener la información del banco: {e}", "warning")

    session["current_company_id"] = company.id

    return render_template(
        "tarjetas.html",
        company=company,
        title="Tarjetas",
        bank_info=bank_info,
    )


@app.route("/empresa/<int:company_id>/tarjetas/activar/<tipo>")
@login_required
@role_required("admin")
def activar_tarjeta(company_id, tipo):
    card_type = CardType.DEBIT if tipo.lower() == "debit" else CardType.CREDIT
    try:
        activate_card(company_id, card_type)
        flash("Tarjeta activada correctamente.", "success")
    except ValueError as e:
        flash(str(e), "danger")
    return redirect(url_for("ver_tarjetas", company_id=company_id))


# ---------------------------------------------------------
# PAGOS
# ---------------------------------------------------------

@app.route("/empresa/<int:company_id>/pagos/nuevo", methods=["GET", "POST"])
@login_required
@role_required("admin")
def nuevo_pago(company_id):
    company = Company.query.get_or_404(company_id)

    if request.method == "POST":
        try:
            amount = float(request.form["amount"])
        except:
            flash("Importe no válido.", "danger")
            return render_template("nuevo_pago.html", company=company)

        desc = request.form.get("description", "")

        # Obtener el usuario logueado
        userinfo = session.get("user", {})
        profile = None
        sub = userinfo.get("sub")
        if sub:
            profile = UserProfile.query.filter_by(keycloak_sub=sub).first()

        try:
            process_payment(company_id, amount, desc, user_profile=profile)
        except ValueError as e:
            flash(str(e), "danger")
            return render_template("nuevo_pago.html", company=company)

        flash("Pago realizado correctamente.", "success")
        return redirect(url_for("listar_pagos", company_id=company_id))

    session["current_company_id"] = company.id
    return render_template("nuevo_pago.html", company=company)



@app.route("/empresa/<int:company_id>/pagos")
@login_required
@role_required("admin")
def listar_pagos(company_id):
    company = Company.query.get_or_404(company_id)
    session["current_company_id"] = company.id

    # Filtros
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    amount_min = request.args.get("amount_min")
    amount_max = request.args.get("amount_max")
    user_name = request.args.get("user_name")  # NUEVO

    q = Transaction.query.filter_by(company_id=company.id)

    if date_from:
        ...
    if date_to:
        ...
    if amount_min:
        ...
    if amount_max:
        ...

    # Filtro por usuario (join con UserProfile)
    if user_name:
        q = q.join(Transaction.user).filter(
            UserProfile.username.ilike(f"%{user_name}%")
        )

    transacciones = q.order_by(Transaction.created_at.desc()).all()
    total = sum(t.amount for t in transacciones)

    return render_template(
        "pagos.html",
        company=company,
        transacciones=transacciones,
        total=total,
        title="Historial de pagos",
    )



@app.route("/empresa/<int:company_id>/pagos/<int:tx_id>/pdf")
@login_required
@role_required("admin")
def pago_pdf(company_id, tx_id):
    company = Company.query.get_or_404(company_id)
    tx = Transaction.query.filter_by(id=tx_id, company_id=company_id).first_or_404()

    html_render = render_template(
        "pago_pdf.html",
        company=company,
        tx=tx,
        title=f"Pago #{tx.id}",
    )
    pdf = HTML(string=html_render).write_pdf()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=pago_{tx.id}.pdf"
    return response


@app.route("/empresa/<int:company_id>/pagos/pdf")
@login_required
@role_required("admin")
def pagos_pdf(company_id):
    company = Company.query.get_or_404(company_id)

    # Reaplicar filtros
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    amount_min = request.args.get("amount_min")
    amount_max = request.args.get("amount_max")
    user_name = request.args.get("user_name")  # NUEVO

    q = Transaction.query.filter_by(company_id=company.id)

    if date_from:
        try:
            q = q.filter(Transaction.created_at >= datetime.strptime(date_from, "%Y-%m-%d"))
        except:
            pass

    if date_to:
        try:
            dt = datetime.strptime(date_to, "%Y-%m-%d")
            dt_end = dt.replace(hour=23, minute=59, second=59)
            q = q.filter(Transaction.created_at <= dt_end)
        except:
            pass

    if amount_min:
        try:
            q = q.filter(Transaction.amount >= float(amount_min))
        except:
            pass

    if amount_max:
        try:
            q = q.filter(Transaction.amount <= float(amount_max))
        except:
            pass

    # Filtro por usuario (igual que en listar_pagos)
    if user_name:
        q = q.join(Transaction.user).filter(
            UserProfile.username.ilike(f"%{user_name}%")
        )

    transacciones = q.order_by(Transaction.created_at.desc()).all()
    total = sum(t.amount for t in transacciones)

    html_render = render_template(
        "pagos_pdf.html",
        company=company,
        transacciones=transacciones,
        total=total,
        title="Informe de pagos filtrados",
    )

    pdf = HTML(string=html_render).write_pdf()
    r = make_response(pdf)
    r.headers["Content-Type"] = "application/pdf"
    r.headers["Content-Disposition"] = "attachment; filename=pagos_filtrados.pdf"
    return r



# ---------------------------------------------------------
# GASTOS (admin + empleado)
# ---------------------------------------------------------

@app.route("/empresa/<int:company_id>/gastos", methods=["GET"])
@login_required
@roles_required("admin", "empleado")
def listar_gastos(company_id):
    company = Company.query.get_or_404(company_id)
    session["current_company_id"] = company.id

    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    amount_min = request.args.get("amount_min")
    amount_max = request.args.get("amount_max")
    user_name = request.args.get("user_name")  # ← NUEVO

    q = Expense.query.filter_by(company_id=company.id)

    if date_from:
        try:
            q = q.filter(Expense.date >= datetime.strptime(date_from, "%Y-%m-%d").date())
        except:
            pass

    if date_to:
        try:
            q = q.filter(Expense.date <= datetime.strptime(date_to, "%Y-%m-%d").date())
        except:
            pass

    if amount_min:
        try:
            q = q.filter(Expense.amount >= float(amount_min))
        except:
            pass

    if amount_max:
        try:
            q = q.filter(Expense.amount <= float(amount_max))
        except:
            pass

    # Filtro por usuario (como en gastos_pdf)
    if user_name:
        q = q.join(Expense.user).filter(
            UserProfile.username.ilike(f"%{user_name}%")
        )

    gastos = q.order_by(Expense.date.desc()).all()
    total = sum(g.amount for g in gastos)

    return render_template(
        "gastos.html",
        company=company,
        gastos=gastos,
        total=total,
        title="Gestión de gastos",
    )



@app.route("/empresa/<int:company_id>/gastos/nuevo", methods=["GET", "POST"])
@login_required
@roles_required("admin", "empleado")
def nuevo_gasto(company_id):
    company = Company.query.get_or_404(company_id)
    session["current_company_id"] = company.id

    if request.method == "POST":
        date_str = request.form.get("date")
        desc = request.form.get("description", "").strip()
        amount_str = request.form.get("amount")

        try:
            date_val = datetime.strptime(date_str, "%Y-%m-%d").date()
        except:
            flash("Fecha no válida.", "danger")
            return render_template("nuevo_gasto.html", company=company)

        try:
            amount = float(amount_str)
        except:
            flash("Importe no válido.", "danger")
            return render_template("nuevo_gasto.html", company=company)

        if amount <= 0:
            flash("El importe debe ser mayor que 0.", "danger")
            return render_template("nuevo_gasto.html", company=company)

        file = request.files.get("ticket")
        ticket_filename = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            ticket_filename = f"{datetime.utcnow().timestamp()}_{filename}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], ticket_filename))

        # NUEVO: obtener el usuario logueado
        userinfo = session.get("user", {})
        profile = None
        sub = userinfo.get("sub")
        if sub:
            profile = UserProfile.query.filter_by(keycloak_sub=sub).first()

        gasto = Expense(
            company_id=company.id,
            date=date_val,
            description=desc,
            amount=amount,
            ticket_filename=ticket_filename,
            user_id=profile.id if profile else None,   # <- aquí guardamos el usuario
        )
        db.session.add(gasto)
        db.session.commit()

        flash("Gasto registrado correctamente.", "success")
        return redirect(url_for("listar_gastos", company_id=company_id))

    return render_template("nuevo_gasto.html", company=company)

@app.route("/empresa/<int:company_id>/gastos/<int:gasto_id>/archivo")
@login_required
@roles_required("admin", "empleado")
def descargar_ticket_gasto(company_id, gasto_id):
    company = Company.query.get_or_404(company_id)
    gasto = Expense.query.filter_by(id=gasto_id, company_id=company.id).first_or_404()

    if not gasto.ticket_filename:
        flash("Este gasto no tiene archivo adjunto.", "warning")
        return redirect(url_for("listar_gastos", company_id=company.id))

    base_folder = app.config.get("UPLOAD_FOLDER")
    filepath = os.path.join(base_folder, gasto.ticket_filename)

    if not os.path.exists(filepath):
        flash("No se ha encontrado el archivo en el servidor.", "danger")
        return redirect(url_for("listar_gastos", company_id=company.id))

    return send_from_directory(
        os.path.dirname(filepath),
        os.path.basename(filepath),
        as_attachment=True,
    )



@app.route("/empresa/<int:company_id>/gastos/<int:gasto_id>/pdf")
@login_required
@roles_required("admin", "empleado")
def gasto_pdf(company_id, gasto_id):
    company = Company.query.get_or_404(company_id)
    gasto = Expense.query.filter_by(id=gasto_id, company_id=company_id).first_or_404()

    html_render = render_template(
        "gasto_pdf.html",
        company=company,
        gasto=gasto,
        title=f"Gasto #{gasto.id}",
    )
    pdf = HTML(string=html_render).write_pdf()

    r = make_response(pdf)
    r.headers["Content-Type"] = "application/pdf"
    r.headers["Content-Disposition"] = f"attachment; filename=gasto_{gasto.id}.pdf"
    return r


@app.route("/empresa/<int:company_id>/gastos/pdf")
@login_required
@roles_required("admin", "empleado")
def gastos_pdf(company_id):
    company = Company.query.get_or_404(company_id)

    # Filtros iguales que en listar_gastos
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    amount_min = request.args.get("amount_min")
    amount_max = request.args.get("amount_max")
    user_name = request.args.get("user_name")  # NUEVO

    q = Expense.query.filter_by(company_id=company.id)

    if date_from:
        try:
            q = q.filter(Expense.date >= datetime.strptime(date_from, "%Y-%m-%d").date())
        except:
            pass

    if date_to:
        try:
            q = q.filter(Expense.date <= datetime.strptime(date_to, "%Y-%m-%d").date())
        except:
            pass

    if amount_min:
        try:
            q = q.filter(Expense.amount >= float(amount_min))
        except:
            pass

    if amount_max:
        try:
            q = q.filter(Expense.amount <= float(amount_max))
        except:
            pass

    # Filtro por usuario (igual que en pagos)
    if user_name:
        q = q.join(Expense.user).filter(
            UserProfile.username.ilike(f"%{user_name}%")
        )

    gastos = q.order_by(Expense.date.desc()).all()
    total = sum(g.amount for g in gastos)

    html_render = render_template(
        "gastos_pdf.html",
        company=company,
        gastos=gastos,
        total=total,
        title="Informe de gastos filtrados",
        now=datetime.utcnow()
    )
    pdf = HTML(string=html_render).write_pdf()

    r = make_response(pdf)
    r.headers["Content-Type"] = "application/pdf"
    r.headers["Content-Disposition"] = "attachment; filename=gastos_filtrados.pdf"
    return r

# ---------------------------------------------------------
# API PARA RECIBIR RESULTADOS DE ESCÁNER (Raspberry Pi)
# ---------------------------------------------------------

@app.route("/api/scan_results", methods=["POST"])
def api_scan_results():
    # 1) Comprobar API KEY
    api_key = request.headers.get("X-API-KEY")
    if api_key != RASPBERRY_API_KEY:
        return jsonify({"error": "API key inválida"}), 401

    # 2) Leer JSON
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "JSON no válido"}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Formato de datos no válido"}), 400

    # 3) Obtener empresa destino
    company_id = request.args.get("company_id", type=int)
    company = None
    if company_id:
        company = Company.query.get(company_id)

    # Si no viene company_id o no existe, usar Empresa Demo
    if not company:
        company = Company.query.filter_by(name="Empresa Demo").first()
        if not company:
            company = Company(
                name="Empresa Demo",
                cif="B12345678",
                email="demo@mkdeh.local",
            )
            db.session.add(company)
            db.session.commit()

    # 4) Transformar datos del escáner en listas "planas"
    open_ports = []
    raw_vulns = []

    hosts = data.get("hosts", [])
    if isinstance(hosts, list):
        for host in hosts:
            if not isinstance(host, dict):
                continue

            host_ip = (
                host.get("ip")
                or host.get("host")
                or host.get("hostname")
                or "desconocido"
            )

            # Soportar tanto "services" como "ports"
            services_list = []

            # Formato antiguo: host["services"] = [...]
            old_services = host.get("services")
            if isinstance(old_services, list):
                services_list.extend(old_services)

            # Formato Raspberry: host["ports"] = [...]
            ports = host.get("ports")
            if isinstance(ports, list):
                for p in ports:
                    if not isinstance(p, dict):
                        continue
                    services_list.append({
                        "port": p.get("port"),
                        "service": p.get("service") or p.get("name") or "desconocido",
                        "state": p.get("state") or "open",
                        # soportar "vulns" o "vulnerabilities"
                        "vulnerabilities": p.get("vulnerabilities")
                            or p.get("vulns")
                            or [],
                    })

            # Recorrer todos los "servicios" normalizados
            for svc in services_list:
                if not isinstance(svc, dict):
                    continue

                port = svc.get("port")
                service_name = svc.get("service") or svc.get("name") or "desconocido"
                state = svc.get("state") or "open"

                # Registro de puerto abierto
                if port is not None:
                    open_ports.append({
                        "host": host_ip,
                        "port": port,
                        "service": service_name,
                        "state": state,
                    })

                # Vulnerabilidades asociadas a ese servicio/puerto
                svc_vulns = (
                    svc.get("vulnerabilities")
                    or svc.get("vulns")
                    or []
                )
                if isinstance(svc_vulns, list):
                    for v in svc_vulns:
                        if isinstance(v, dict):
                            raw_vulns.append(v)

    # 5) Reducir y limpiar vulnerabilidades para que quepan en TEXT
    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }
    MAX_VULNS = 150
    MAX_DESC_LEN = 200

    def vulns_sort_key(v):
        sev = str(v.get("severity", "")).lower()
        sev_rank = SEVERITY_ORDER.get(sev, 9)
        try:
            cvss = float(v.get("cvss", 0))
        except Exception:
            cvss = 0.0
        return (sev_rank, -cvss)

    raw_vulns_sorted = sorted(raw_vulns, key=vulns_sort_key)
    trimmed_vulns = raw_vulns_sorted[:MAX_VULNS]

    cleaned_vulns = []
    for v in trimmed_vulns:
        desc = v.get("description") or ""
        if len(desc) > MAX_DESC_LEN:
            desc = desc[:MAX_DESC_LEN] + "..."
        cleaned_vulns.append({
            "cve": v.get("cve"),
            "cvss": v.get("cvss"),
            "severity": v.get("severity"),
            "description": desc,
            "published": v.get("published"),
            "updated": v.get("updated"),
        })

    # 6) Guardar en BD
    scan = ScanResult(company_id=company.id)
    scan.open_ports = open_ports          # usa el @property del modelo
    scan.vulnerabilities = cleaned_vulns  # idem

    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "status": "ok",
        "scan_id": scan.id,
        "company_id": company.id,
        "open_ports_count": len(open_ports),
        "vulnerabilities_total_original": len(raw_vulns),
        "vulnerabilities_saved": len(cleaned_vulns),
    }), 201



# ---------------------------------------------------------
# ANÁLISIS DE SEGURIDAD
# ---------------------------------------------------------

@app.route("/empresa/<int:company_id>/analisis")
@login_required
@role_required("admin")
def listar_analisis(company_id):
    roles = session.get("roles", [])
    
    if "admin" not in roles:
    	flash("No tienes permisos para realizar esta acción.", "danger")
    	return redirect(url_for("index"))


    company = Company.query.get_or_404(company_id)
    scans = (
        ScanResult.query
        .filter_by(company_id=company.id)
        .order_by(ScanResult.created_at.desc())
        .all()
    )

    auto_refresh = request.args.get("auto_refresh") == "1"
    last_known = request.args.get("last_known", type=int)

    current_latest = scans[0].id if scans else None

    scan_done = request.args.get("scan_done") == "1"

    return render_template(
        "analisis.html",
        title="Análisis de seguridad",
        company=company,
        scans=scans,
        auto_refresh=auto_refresh,
        last_known=last_known,
        current_latest=current_latest,
	scan_done=scan_done,
    )

@app.get("/empresa/<int:company_id>/analisis/ultimo_id_json")
@login_required
def ultimo_id_analisis_json(company_id):
    last_scan = (
        ScanResult.query
        .filter_by(company_id=company_id)
        .order_by(ScanResult.id.desc())
        .first()
    )
    return jsonify({"latest_id": last_scan.id if last_scan else 0})


def validar_rango_ips(start_ip_str: str, end_ip_str: str) -> tuple[str, str]:
    """
    Valida que start_ip y end_ip sean IPv4 válidas y que el último octeto
    esté entre 1 y 255. Además comprueba que start_ip <= end_ip.
    """
    try:
        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)
    except ValueError:
        raise ValueError("Las IPs no tienen un formato válido.")

    if start_ip.version != 4 or end_ip.version != 4:
        raise ValueError("Solo se permiten direcciones IPv4.")

    # Último octeto de cada IP
    start_last = int(str(start_ip).split(".")[-1])
    end_last = int(str(end_ip).split(".")[-1])

    # Restricciones que quieres
    if start_last < 1:
        raise ValueError(
            "La IP de inicio debe terminar en un número entre 1 y 255 (mínimo 1)."
        )
    if end_last > 255:
        raise ValueError(
            "La IP final debe terminar en un número entre 1 y 255 (máximo 255)."
        )

    if start_ip > end_ip:
        raise ValueError("La IP de inicio no puede ser mayor que la IP final.")

    # Devolvemos normalizadas
    return str(start_ip), str(end_ip)


import requests
from requests.exceptions import RequestException

@app.route("/analisis/ejecutar/<int:company_id>", methods=["POST"])
@login_required
@role_required("admin")
def ejecutar_analisis(company_id):
    start_ip_raw = request.form.get("start_ip", "").strip()
    end_ip_raw = request.form.get("end_ip", "").strip()

    if not start_ip_raw or not end_ip_raw:
        flash("Debes introducir rango de IPs", "danger")
        return redirect(url_for("listar_analisis", company_id=company_id))

    # ✅ Validación de rango y último octeto (1–255)
    try:
        start_ip, end_ip = validar_rango_ips(start_ip_raw, end_ip_raw)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("listar_analisis", company_id=company_id))

    # Análisis más reciente ANTES de comenzar este escaneo
    last_scan = (
        ScanResult.query
        .filter_by(company_id=company_id)
        .order_by(ScanResult.created_at.desc())
        .first()
    )
    last_known = last_scan.id if last_scan else 0

    payload = {
        "start_ip": start_ip,
        "end_ip": end_ip,
        "company_id": company_id,
    }

    try:
        r = requests.post(
            f"{RASPBERRY_BASE_URL}/run_scan",
            json=payload,
            timeout=5,
        )
        if r.status_code == 200:
            flash("Escaneo iniciado en la Raspberry", "success")
        else:
            flash(f"Error: la Raspberry devolvió {r.status_code}", "danger")
    except Exception as e:
        flash(f"No se pudo contactar con la Raspberry: {e}", "danger")

    return redirect(
        url_for(
            "listar_analisis",
            company_id=company_id,
            auto_refresh=1,
            last_known=last_known,
        )
    )

# -------------------------------------------------
# DETENER ESCANEO
# -------------------------------------------------

@app.route("/analisis/detener/<int:company_id>", methods=["POST"])
@login_required
@role_required("admin")
def detener_analisis(company_id):
    try:
        r = requests.post(f"{RASPBERRY_BASE_URL}/analisis/stop", timeout=5)
        if r.status_code == 200:
            flash("Se ha enviado la orden de detener el escaneo en la Raspberry.", "warning")
        else:
            flash(f"No se pudo detener el escaneo. La Raspberry devolvió {r.status_code}.", "danger")
    except Exception as e:
        flash(f"No se pudo contactar con la Raspberry para detener el escaneo: {e}", "danger")

    return redirect(url_for("listar_analisis", company_id=company_id))


@app.route("/empresa/<int:company_id>/analisis/importar", methods=["POST"])
@login_required
@role_required("admin")
def importar_analisis_desde_raspi(company_id):
    company = Company.query.get_or_404(company_id)

    try:
        # 1) Pedimos el JSON a la Raspberry
        raspi_url = f"{RASPBERRY_BASE_URL}/get-json"
        r = requests.get(raspi_url, timeout=10)

        if r.status_code != 200:
            flash(
                f"La Raspberry ha devuelto un error al pedir el JSON (código {r.status_code}).",
                "danger",
            )
            return redirect(url_for("listar_analisis", company_id=company.id))

        try:
            data = r.json()
        except Exception as e:
            flash(f"El JSON recibido de la Raspberry no es válido: {e}", "danger")
            return redirect(url_for("listar_analisis", company_id=company.id))

        # 2) Reutilizamos nuestro propio endpoint /api/scan_results
        #    para transformar y guardar en BD, pasándole company_id
        internal_url = url_for("api_scan_results", company_id=company.id, _external=True)

        r2 = requests.post(
            internal_url,
            headers={"X-API-KEY": RASPBERRY_API_KEY, "Content-Type": "application/json"},
            json=data,
            timeout=10,
            verify=False,  # <--- clave para ignorar el certificado autofirmado
        )

        if r2.status_code not in (200, 201):
            flash(
                f"No se ha podido guardar el análisis en el servidor "
                f"(código {r2.status_code}).",
                "danger",
            )
        else:
            resp_data = r2.json()
            scan_id = resp_data.get("scan_id")
            flash(
                f"Análisis importado correctamente desde la Raspberry "
                f"(ID interno {scan_id}).",
                "success",
            )

    except RequestException as e:
        flash(
            f"No se ha podido contactar con la Raspberry en {RASPBERRY_BASE_URL}: {e}",
            "danger",
        )
    except Exception as e:
        flash(f"Error inesperado al importar el análisis: {e}", "danger")

    return redirect(url_for("listar_analisis", company_id=company.id))


@app.route("/empresa/<int:company_id>/analisis/<int:scan_id>")
@login_required
@role_required("admin")
def detalle_analisis(company_id, scan_id):
    company = Company.query.get_or_404(company_id)
    session["current_company_id"] = company.id

    scan = ScanResult.query.filter_by(id=scan_id, company_id=company_id).first_or_404()

    open_ports = scan.open_ports or []
    vulns = scan.vulnerabilities or []

    hosts = sorted({p.get("host") for p in open_ports if isinstance(p, dict) and p.get("host")})

    services = {}
    for p in open_ports:
        if not isinstance(p, dict):
            continue
        svc = p.get("service") or "desconocido"
        port = p.get("port")
        if port is None:
            continue
        services.setdefault(svc, [])
        if port not in services[svc]:
            services[svc].append(port)

    for svc in services:
        services[svc].sort()

    severity_counts = {"high": 0, "medium": 0, "low": 0, "other": 0}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        sev = str(v.get("severity", "")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return render_template(
        "analisis_detalle.html",
        company=company,
        scan=scan,
        hosts=hosts,
        services=services,
        severity_counts=severity_counts,
        vulnerabilities=vulns,
        title=f"Detalle análisis #{scan.id}",
    )


@app.route("/empresa/<int:company_id>/analisis/<int:scan_id>/pdf")
@login_required
@role_required("admin")
def analisis_pdf(company_id, scan_id):
    company = Company.query.get_or_404(company_id)
    scan = ScanResult.query.filter_by(id=scan_id, company_id=company_id).first_or_404()

    html_render = render_template(
        "analisis_pdf.html",
        company=company,
        scan=scan,
        title=f"Informe de análisis #{scan.id}",
    )
    pdf = HTML(string=html_render).write_pdf()

    r = make_response(pdf)
    r.headers["Content-Type"] = "application/pdf"
    r.headers["Content-Disposition"] = f"attachment; filename=analisis_{scan.id}.pdf"
    return r


# ---------------------------------------------------------
# MANEJADORES DE ERRORES
# ---------------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html", title="Página no encontrada"), 404


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=False)

