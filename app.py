from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from functools import wraps
from datetime import datetime, timedelta
import random
import requests as http_requests
import pyotp
import qrcode
import os
from db import get_connection


# -----------------------------------------------
# BLOQUEO / BANEO POR IP
# -----------------------------------------------
from collections import defaultdict
from flask import abort

# Configuración
MAX_INTENTOS_IP = 3          # intentos fallidos permitidos
TIEMPO_BLOQUEO = 2          # minutos bloqueado

# Estructura:
# {
#   "IP": {
#       "intentos": 0,
#       "bloqueado_hasta": datetime
#   }
# }
ip_bloqueadas = defaultdict(lambda: {
    "intentos": 0,
    "bloqueado_hasta": None
})


def obtener_ip():
    """Obtiene la IP real del cliente."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr


def ip_esta_bloqueada(ip):
    datos = ip_bloqueadas[ip]

    if datos["bloqueado_hasta"]:
        if datetime.now() < datos["bloqueado_hasta"]:
            return True
        else:
            # Desbloquear automáticamente
            datos["intentos"] = 0
            datos["bloqueado_hasta"] = None

    return False


def registrar_intento_fallido(ip):
    datos = ip_bloqueadas[ip]
    datos["intentos"] += 1

    if datos["intentos"] >= MAX_INTENTOS_IP:
        datos["bloqueado_hasta"] = datetime.now() + timedelta(minutes=TIEMPO_BLOQUEO)
        app.logger.warning(f"IP BLOQUEADA: {ip}")


def limpiar_intentos(ip):
    ip_bloqueadas[ip]["intentos"] = 0
    ip_bloqueadas[ip]["bloqueado_hasta"] = None
app = Flask(__name__)
app.config["RECAPTCHA_SITE_KEY"]= "6Lf9DewsAAAAAOheKGcWv1T9Iuv3TOTeoFpyer9P"
app.config["RECAPTCHA_SECRET_KEY"]= "6Lf9DewsAAAAAPPgh6PVZgV-IhWNjamnJtKYAjBZ"
app.secret_key = "moova_clave_secreta_2025"
bcrypt = Bcrypt(app)


#-----------------------------------------
#RECAPTCHA
#-----------------------------------------

def verificar_recaptcha(token):
    secret_key = app.config["RECAPTCHA_SECRET_KEY"]
    response = http_requests.post(
        "https://www.google.com/recaptcha/api/siteverify", data={
            "secret": secret_key,
            "response":token
        }
    )
    result=response.json()
    return result.get("success", False)
# -----------------------------------------------
# CONFIGURACIÓN — rellena estos valores
# -----------------------------------------------
APIPERU_TOKEN    = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6ImkyNTEzMzE2QGNvbnRpbmVudGFsLmVkdS5wZSJ9.6g2z_4YcwV2hzlMgLyXmODt-_BNAqY99bEeQ99qsWCg"          # apiperu.dev
APIPERU_URL      = "https://dniruc.apisperu.com/api/v1/dni/{dni}?token={token}"

# TextBee — regístrate gratis en https://textbee.dev
# Instala la app Android, conecta tu celular y copia estos datos
TEXTBEE_API_KEY  = "f16f2d18-6730-419a-b8b3-699504af41dc"        # Settings → API Key
TEXTBEE_DEVICE_ID = "69e93ff9b5cd3ce4c753c83c"    # Dashboard → tu dispositivo
TEXTBEE_URL      = "https://api.textbee.dev/api/v1/gateway/devices/{device_id}/send-sms"

API_KEY          = "moova-api-2025-xK9mP3qL"  # para tu propia API REST

OTP_EXPIRA_MIN   = 10   # minutos antes de que expire el código
OTP_MAX_INTENTOS = 3    # intentos fallidos antes de invalidar


# -----------------------------------------------
# HELPERS OTP
# -----------------------------------------------
def generar_otp():
    return str(random.randint(100000, 999999))


def enviar_sms_otp(telefono, codigo, accion):
    """Envía el SMS con el código OTP via TextBee (https://textbee.dev)."""
    verbo = "modificar" if accion == "modificar" else "cancelar"
    mensaje = (
        f"MOOVA Clinic: Tu codigo para {verbo} tu cita es {codigo}. "
        f"Valido por {OTP_EXPIRA_MIN} minutos. "
        f"No compartas este codigo."
    )
    try:
        # Normalizar teléfono peruano: 9XXXXXXXX → +519XXXXXXXX
        tel = telefono.strip().replace(" ", "").replace("-", "")
        if tel.startswith("0"):
            tel = tel[1:]
        if not tel.startswith("+"):
            tel = "+51" + tel

        url = TEXTBEE_URL.format(device_id=TEXTBEE_DEVICE_ID)
        resp = http_requests.post(
            url,
            json={"recipients": [tel], "message": mensaje},
            headers={"x-api-key": TEXTBEE_API_KEY},
            timeout=10
        )
        if resp.status_code in (200, 201):
            return True
        app.logger.error(f"TextBee error {resp.status_code}: {resp.text}")
        return False
    except Exception as e:
        app.logger.error(f"TextBee error: {e}")
        return False


def guardar_otp(dni, codigo, accion):
    """Guarda el OTP en BD, invalidando cualquier código anterior del mismo DNI+accion."""
    expira = datetime.now() + timedelta(minutes=OTP_EXPIRA_MIN)
    conn   = get_connection()
    cursor = conn.cursor()
    # Invalidar OTPs anteriores para este DNI y acción
    cursor.execute(
        "UPDATE otp_verificaciones SET usado = 1 WHERE dni = %s AND accion = %s AND usado = 0",
        (dni, accion)
    )
    cursor.execute(
        "INSERT INTO otp_verificaciones (dni, codigo, accion, expira_en) VALUES (%s, %s, %s, %s)",
        (dni, codigo, accion, expira)
    )
    conn.commit()
    conn.close()


def verificar_otp(dni, codigo_ingresado, accion):
    """
    Verifica el OTP. Retorna:
      'ok'        — código correcto
      'incorrecto'— código incorrecto (incrementa intentos)
      'expirado'  — pasaron los 10 min
      'agotado'   — superó los intentos máximos
      'no_existe' — no hay OTP activo
    """
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM otp_verificaciones
        WHERE dni = %s AND accion = %s AND usado = 0
        ORDER BY creado_en DESC
        LIMIT 1
    """, (dni, accion))
    otp = cursor.fetchone()

    if not otp:
        conn.close()
        return "no_existe"

    if otp["intentos"] >= OTP_MAX_INTENTOS:
        conn.close()
        return "agotado"

    if datetime.now() > otp["expira_en"]:
        conn.close()
        return "expirado"

    if otp["codigo"] != codigo_ingresado.strip():
        cursor.execute(
            "UPDATE otp_verificaciones SET intentos = intentos + 1 WHERE id = %s",
            (otp["id"],)
        )
        conn.commit()
        conn.close()
        restantes = OTP_MAX_INTENTOS - otp["intentos"] - 1
        return f"incorrecto:{restantes}"

    # Código correcto → marcar como usado
    cursor.execute(
        "UPDATE otp_verificaciones SET usado = 1 WHERE id = %s",
        (otp["id"],)
    )
    conn.commit()
    conn.close()
    return "ok"


# -----------------------------------------------
# HELPER APISperú
# -----------------------------------------------
def consultar_dni_apiperu(dni):
    try:
        url = APIPERU_URL.format(dni=dni, token=APIPERU_TOKEN)
        resp = http_requests.get(url, headers={"Accept": "application/json"},timeout=5)  
        app.logger.error(f'Consultar APISPerú: {resp.status_code}{resp.text}')
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success"):
                return data
    except Exception as e:
        app.logger.error(f"Error al consultar DNI {dni}: {e}")
    return None


# -----------------------------------------------
# DECORADORES
# -----------------------------------------------
# -----------------------------------------------
# DECORADORES
# -----------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        ip = obtener_ip()

        # Verificar bloqueo IP
        if ip_esta_bloqueada(ip):
            flash(f"Tu IP está bloqueada temporalmente por {TIEMPO_BLOQUEO} minutos.")
            return redirect(url_for("login"))

        # Verificar sesión
        if "usuario" not in session and "admin" not in session:

            registrar_intento_fallido(ip)

            flash("Debes iniciar sesión.")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        ip = obtener_ip()

        # Verificar bloqueo IP
        if ip_esta_bloqueada(ip):
            flash(f"Tu IP está bloqueada temporalmente por {TIEMPO_BLOQUEO} minutos.")
            return redirect(url_for("login"))

        # Verificar administrador
        if "admin" not in session:

            registrar_intento_fallido(ip)

            flash("Acceso denegado.")
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated_function


def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        ip = obtener_ip()

        # Verificar si la IP está bloqueada
        if ip_esta_bloqueada(ip):
            return jsonify({
                "error": "IP bloqueada temporalmente"
            }), 403

        # Verificar API KEY
        api_key = request.headers.get("X-API-Key", "")

        if api_key != API_KEY:

            registrar_intento_fallido(ip)

            return jsonify({
                "error": "API key invalida o ausente"
            }), 401

        # API KEY correcta
        limpiar_intentos(ip)

        return f(*args, **kwargs)

    return decorated

# -----------------------------------------------
# INICIO
# -----------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# -----------------------------------------------
# LOGIN / LOGOUT
# -----------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    ip=obtener_ip()

    #Recapcha
    recaptcha_response = request.form.get("g-recaptcha-response")

        # DEBUG
    print("TOKEN RECAPTCHA:", recaptcha_response)

    if not recaptcha_response:
            flash("Debes completar el reCAPTCHA.")
            return redirect(url_for("login"))

    if not verificar_recaptcha(recaptcha_response):
            flash("Verifica correctamente el reCAPTCHA.")
            return redirect(url_for("login"))
        # -----------------------------
        # OBTENER DATOS LOGIN
        # -----------------------------
    correo = request.form.get("correo", "").strip()
    clave = request.form.get("clave", "").strip()

    if not correo or not clave:
            flash("Completa todos los campos.")
            return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    #verificar si la IP está bloqueada
    if ip_esta_bloqueada(ip):
        flash(f"Tu IP ha sido bloqueada temporalmente por demasiados intentos fallidos. Intenta nuevamente en {TIEMPO_BLOQUEO} minutos.")
        return render_template("login.html")
    if request.method == "POST":
        correo = request.form["correo"].strip()
        clave  = request.form["clave"].strip()

        if not correo or not clave:
            flash("Completa todos los campos.")
            return redirect(url_for("login"))

        conn   = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM admins WHERE correo = %s", (correo,))
        admin = cursor.fetchone()

        if admin:
            if bcrypt.check_password_hash(admin["clave"], clave):
                session["admin"]    = admin["nombre"]
                session["admin_id"] = admin["id"]
                limpiar_intentos(ip)
                conn.close()
                return redirect(url_for("panel_admin"))
            else:
                registrar_intento_fallido(ip)
                flash("Contrasena incorrecta.")
                conn.close()
                return redirect(url_for("login"))

        cursor.execute("SELECT * FROM terapeutas WHERE Correo = %s", (correo,))
        medico = cursor.fetchone()
        conn.close()

        if medico:
            if bcrypt.check_password_hash(medico["Clave"], clave):
                session["usuario"]   = medico["Nombre"]
                session["medico_id"] = medico["ID"]
                limpiar_intentos(ip)
                return redirect(url_for("interfaz"))
            else:
                registrar_intento_fallido(ip)
                flash("Contrasena incorrecta.")
        else:
            registrar_intento_fallido(ip)
        flash("El usuario no existe.")

        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------
# MÓDULO CITAS — agendar
# -----------------------------------------------
@app.route("/citas", methods=["GET", "POST"])
def citas():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT ID, Nombre, Especialidad FROM terapeutas")
    terapeutas = cursor.fetchall()

    if request.method == "POST":
        nombre     = request.form.get("nombre", "").strip()
        apellido   = request.form.get("apellido", "").strip()
        dni        = request.form.get("dni", "").strip()
        telefono   = request.form.get("telefono", "").strip()
        medico_id  = request.form.get("medico_id", "").strip()
        fecha_cita = request.form.get("fecha_cita", "").strip()

        if not all([nombre, apellido, dni, telefono, medico_id, fecha_cita]):
            flash("campos_vacios")
            conn.close()
            return redirect(url_for("citas"))

        try:
            fecha_obj = datetime.strptime(fecha_cita, "%Y-%m-%d").date()
            if fecha_obj < datetime.today().date():
                flash("fecha_pasada")
                conn.close()
                return redirect(url_for("citas"))
        except ValueError:
            flash("campos_vacios")
            conn.close()
            return redirect(url_for("citas"))

        cursor.execute("SELECT id FROM personas WHERE dni = %s", (dni,))
        persona = cursor.fetchone()

        if persona:
            persona_id = persona["id"]
        else:
            cursor.execute(
                "INSERT INTO personas (nombre, apellido, dni, telefono) VALUES (%s, %s, %s, %s)",
                (nombre, apellido, dni, telefono)
            )
            conn.commit()
            persona_id = cursor.lastrowid

        cursor.execute(
            "INSERT INTO historial_citas (persona_id, terapeuta_id, fecha_cita, estado) VALUES (%s, %s, %s, 'programada')",
            (persona_id, medico_id, fecha_cita)
        )
        conn.commit()
        cita_id = cursor.lastrowid
        conn.close()
        return redirect(url_for("retorno", cita_id=cita_id))

    conn.close()
    return render_template("citas.html", terapeutas=terapeutas)


# ── AJAX: autocompletar nombre con APISperú ───────────────────────────────────
@app.route("/api/verificar_dni", methods=["POST"])
def verificar_dni_ajax():
    dni = (request.json or {}).get("dni", "").strip()
    if len(dni) != 8 or not dni.isdigit():
        return jsonify({"success": False, "error": "DNI invalido"}), 400
    data = consultar_dni_apiperu(dni)
    if data:
        return jsonify({"success": True, "data": data})
    return jsonify({"success": False, "error": "DNI no encontrado"}), 404
app.logger.info(f"Llamando a APISPerú con dni: {consultar_dni_apiperu}")
app.logger.info(f"URL:{url_for}")

# ═══════════════════════════════════════════════
# MODIFICAR CITA — flujo OTP de 3 pasos
#
#  Paso 1 (accion=solicitar): DNI → busca teléfono → envía SMS → muestra input OTP
#  Paso 2 (accion=verificar): OTP correcto → muestra citas para editar
#  Paso 3 (accion=guardar):   guarda cambios
# ═══════════════════════════════════════════════
@app.route("/citas/modificar", methods=["GET", "POST"])
def modificar_cita():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT ID, Nombre, Especialidad FROM terapeutas")
    terapeutas = cursor.fetchall()

    if request.method == "POST":
        accion = request.form.get("accion")

        # ── PASO 1: recibir DNI y enviar OTP ─────────────────────────────────
        if accion == "solicitar":
            dni = request.form.get("dni", "").strip()

            if not dni or len(dni) != 8 or not dni.isdigit():
                conn.close()
                return render_template("modificar_cita.html",
                    error="Ingresa un DNI válido (8 dígitos).",
                    terapeutas=terapeutas)

            # Verificar que el paciente exista y tenga citas programadas
            cursor.execute("""
                SELECT p.telefono FROM personas p
                JOIN historial_citas h ON h.persona_id = p.id
                WHERE p.dni = %s AND h.estado = 'programada'
                LIMIT 1
            """, (dni,))
            persona = cursor.fetchone()
            conn.close()

            if not persona:
                return render_template("modificar_cita.html",
                    error="No se encontraron citas programadas para ese DNI.",
                    terapeutas=terapeutas)

            # Generar OTP y enviar SMS
            codigo = generar_otp()
            guardar_otp(dni, codigo, "modificar")
            enviado = enviar_sms_otp(persona["telefono"], codigo, "modificar")

            if not enviado:
                return render_template("modificar_cita.html",
                    error="No se pudo enviar el SMS. Intenta de nuevo.",
                    terapeutas=terapeutas)

            # Mostrar teléfono enmascarado: 987***321
            tel = persona["telefono"].strip()
            tel_mask = tel[:3] + "***" + tel[-3:] if len(tel) >= 6 else "***"

            return render_template("modificar_cita.html",
                paso="verificar", dni=dni, tel_mask=tel_mask,
                terapeutas=terapeutas)

        # ── PASO 2: verificar OTP ─────────────────────────────────────────────
        elif accion == "verificar":
            dni    = request.form.get("dni", "").strip()
            codigo = request.form.get("otp", "").strip()

            resultado = verificar_otp(dni, codigo, "modificar")

            if resultado == "ok":
                # OTP correcto → buscar citas
                cursor.execute("""
                    SELECT h.id, h.fecha_cita, h.estado,
                           p.nombre, p.apellido, p.dni,
                           t.Nombre AS terapeuta, t.Especialidad, h.terapeuta_id
                    FROM historial_citas h
                    JOIN personas p ON h.persona_id = p.id
                    JOIN terapeutas t ON h.terapeuta_id = t.ID
                    WHERE p.dni = %s AND h.estado = 'programada'
                    ORDER BY h.fecha_cita ASC
                """, (dni,))
                citas_encontradas = cursor.fetchall()
                conn.close()
                return render_template("modificar_cita.html",
                    citas=citas_encontradas, terapeutas=terapeutas,
                    verificado=True)

            conn.close()
            mensajes = {
                "expirado":  "El código expiró. Solicita uno nuevo.",
                "agotado":   f"Superaste los {OTP_MAX_INTENTOS} intentos. Solicita un nuevo código.",
                "no_existe": "No hay un código activo. Solicita uno nuevo.",
            }
            if resultado.startswith("incorrecto:"):
                restantes = resultado.split(":")[1]
                error_msg = f"Código incorrecto. Te quedan {restantes} intento(s)."
            else:
                error_msg = mensajes.get(resultado, "Error de verificación.")

            # Re-mostrar pantalla OTP con el error
            tel_mask = "***"
            return render_template("modificar_cita.html",
                paso="verificar", dni=dni, tel_mask=tel_mask,
                error=error_msg, terapeutas=terapeutas)

        # ── PASO 3: guardar cambios ───────────────────────────────────────────
        elif accion == "guardar":
            cita_id      = request.form.get("cita_id")
            nueva_fecha  = request.form.get("fecha_cita", "").strip()
            nuevo_medico = request.form.get("medico_id", "").strip()

            if not cita_id or not nueva_fecha or not nuevo_medico:
                flash("Completa todos los campos para modificar.")
                conn.close()
                return redirect(url_for("modificar_cita"))

            try:
                fecha_obj = datetime.strptime(nueva_fecha, "%Y-%m-%d").date()
                if fecha_obj < datetime.today().date():
                    flash("La nueva fecha no puede ser en el pasado.")
                    conn.close()
                    return redirect(url_for("modificar_cita"))
            except ValueError:
                flash("Fecha invalida.")
                conn.close()
                return redirect(url_for("modificar_cita"))

            cursor.execute(
                "UPDATE historial_citas SET fecha_cita = %s, terapeuta_id = %s WHERE id = %s",
                (nueva_fecha, nuevo_medico, cita_id)
            )
            conn.commit()
            conn.close()
            flash("exito:Cita modificada correctamente.")
            return redirect(url_for("modificar_cita"))

    conn.close()
    return render_template("modificar_cita.html", terapeutas=terapeutas)


# ═══════════════════════════════════════════════
# CANCELAR CITA — flujo OTP de 3 pasos (igual)
# ═══════════════════════════════════════════════
@app.route("/citas/cancelar", methods=["GET", "POST"])
def cancelar_cita():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        accion = request.form.get("accion")

        # ── PASO 1 ────────────────────────────────────────────────────────────
        if accion == "solicitar":
            dni = request.form.get("dni", "").strip()

            if not dni or len(dni) != 8 or not dni.isdigit():
                conn.close()
                return render_template("cancelar_cita.html",
                    error="Ingresa un DNI válido (8 dígitos).")

            cursor.execute("""
                SELECT p.telefono FROM personas p
                JOIN historial_citas h ON h.persona_id = p.id
                WHERE p.dni = %s AND h.estado = 'programada'
                LIMIT 1
            """, (dni,))
            persona = cursor.fetchone()
            conn.close()

            if not persona:
                return render_template("cancelar_cita.html",
                    error="No se encontraron citas programadas para ese DNI.")

            codigo  = generar_otp()
            guardar_otp(dni, codigo, "cancelar")
            enviado = enviar_sms_otp(persona["telefono"], codigo, "cancelar")

            if not enviado:
                return render_template("cancelar_cita.html",
                    error="No se pudo enviar el SMS. Intenta de nuevo.")

            tel = persona["telefono"].strip()
            tel_mask = tel[:3] + "***" + tel[-3:] if len(tel) >= 6 else "***"

            return render_template("cancelar_cita.html",
                paso="verificar", dni=dni, tel_mask=tel_mask)

        # ── PASO 2 ────────────────────────────────────────────────────────────
        elif accion == "verificar":
            dni    = request.form.get("dni", "").strip()
            codigo = request.form.get("otp", "").strip()

            resultado = verificar_otp(dni, codigo, "cancelar")

            if resultado == "ok":
                cursor.execute("""
                    SELECT h.id, h.fecha_cita, h.estado,
                           p.nombre, p.apellido, p.dni,
                           t.Nombre AS terapeuta, t.Especialidad
                    FROM historial_citas h
                    JOIN personas p ON h.persona_id = p.id
                    JOIN terapeutas t ON h.terapeuta_id = t.ID
                    WHERE p.dni = %s AND h.estado = 'programada'
                    ORDER BY h.fecha_cita ASC
                """, (dni,))
                citas_encontradas = cursor.fetchall()
                conn.close()
                return render_template("cancelar_cita.html",
                    citas=citas_encontradas, verificado=True)

            conn.close()
            mensajes = {
                "expirado":  "El código expiró. Solicita uno nuevo.",
                "agotado":   f"Superaste los {OTP_MAX_INTENTOS} intentos. Solicita un nuevo código.",
                "no_existe": "No hay un código activo. Solicita uno nuevo.",
            }
            if resultado.startswith("incorrecto:"):
                restantes = resultado.split(":")[1]
                error_msg = f"Código incorrecto. Te quedan {restantes} intento(s)."
            else:
                error_msg = mensajes.get(resultado, "Error de verificación.")

            tel_mask = "***"
            return render_template("cancelar_cita.html",
                paso="verificar", dni=dni, tel_mask=tel_mask,
                error=error_msg)

        # ── PASO 3 ────────────────────────────────────────────────────────────
        elif accion == "confirmar":
            cita_id = request.form.get("cita_id")
            cursor.execute(
                "UPDATE historial_citas SET estado = 'cancelada' WHERE id = %s",
                (cita_id,)
            )
            conn.commit()
            conn.close()
            flash("exito:Tu cita ha sido cancelada correctamente.")
            return redirect(url_for("cancelar_cita"))

    conn.close()
    return render_template("cancelar_cita.html")


@app.route("/retorno")
def retorno():
    cita_id = request.args.get("cita_id")
    return render_template("retorno.html", cita_id=cita_id)


# -----------------------------------------------
# INTERFAZ TERAPEUTA / ADMIN
# -----------------------------------------------
@app.route("/interfaz")
@login_required
def interfaz():
    fecha_str = request.args.get("fecha", datetime.today().strftime("%Y-%m-%d"))

    try:
        fecha_obj = datetime.strptime(fecha_str, "%Y-%m-%d")
    except ValueError:
        fecha_obj = datetime.today()

    ayer          = (fecha_obj - timedelta(days=1)).strftime("%Y-%m-%d")
    manana        = (fecha_obj + timedelta(days=1)).strftime("%Y-%m-%d")
    dias          = ["Domingo", "Lunes", "Martes", "Miercoles", "Jueves", "Viernes", "Sabado"]
    dia_semana    = dias[fecha_obj.weekday() + 1 if fecha_obj.weekday() < 6 else 0]
    fecha_display = fecha_obj.strftime("%d/%m/%Y")
    es_hoy        = fecha_str == datetime.today().strftime("%Y-%m-%d")
    es_admin      = "admin" in session

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    if es_admin:
        cursor.execute("""
            SELECT p.id, p.nombre, p.apellido, p.dni, p.telefono,
                   h.id AS historial_id, h.descripcion, h.estado,
                   t.Nombre AS terapeuta,
                   (SELECT COUNT(*) FROM historial_citas WHERE persona_id = p.id) AS total_visitas
            FROM personas p
            JOIN historial_citas h ON h.persona_id = p.id
            JOIN terapeutas t ON h.terapeuta_id = t.ID
            WHERE h.fecha_cita = %s AND h.estado = 'programada'
            ORDER BY p.apellido ASC
        """, (fecha_str,))
    else:
        cursor.execute("""
            SELECT p.id, p.nombre, p.apellido, p.dni, p.telefono,
                   h.id AS historial_id, h.descripcion, h.estado,
                   t.Nombre AS terapeuta,
                   (SELECT COUNT(*) FROM historial_citas WHERE persona_id = p.id) AS total_visitas
            FROM personas p
            JOIN historial_citas h ON h.persona_id = p.id
            JOIN terapeutas t ON h.terapeuta_id = t.ID
            WHERE h.fecha_cita = %s AND h.terapeuta_id = %s AND h.estado = 'programada'
            ORDER BY p.apellido ASC
        """, (fecha_str, session.get("medico_id")))

    pacientes = cursor.fetchall()
    conn.close()

    nombre_usuario = session.get("admin") or session.get("usuario")

    return render_template(
        "interfaz.html",
        pacientes=pacientes,
        fecha_actual=fecha_str,
        fecha_display=fecha_display,
        dia_semana=dia_semana,
        ayer=ayer,
        manana=manana,
        es_hoy=es_hoy,
        nombre_usuario=nombre_usuario,
        es_admin=es_admin
    )


@app.route("/guardar_descripcion", methods=["POST"])
@login_required
def guardar_descripcion():
    historial_id = request.form.get("historial_id")
    descripcion  = request.form.get("descripcion", "").strip()
    fecha        = request.form.get("fecha", datetime.today().strftime("%Y-%m-%d"))

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE historial_citas SET descripcion = %s, estado = 'completada' WHERE id = %s",
        (descripcion, historial_id)
    )
    conn.commit()
    conn.close()
    return redirect(url_for("interfaz", fecha=fecha))


# -----------------------------------------------
# PANEL ADMIN
# -----------------------------------------------
@app.route("/panel_admin", methods=["GET", "POST"])
@admin_required
def panel_admin():
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        accion = request.form.get("accion")

        if accion == "registrar":
            nombre       = request.form.get("nombre", "").strip()
            especialidad = request.form.get("especialidad", "").strip()
            correo       = request.form.get("correo", "").strip()
            clave        = request.form.get("clave", "").strip()

            if nombre and especialidad and correo and clave:
                cursor.execute("SELECT ID FROM terapeutas WHERE Correo = %s", (correo,))
                if cursor.fetchone():
                    flash("Ya existe un medico con ese correo.")
                else:
                    clave_hash = bcrypt.generate_password_hash(clave).decode("utf-8")
                    cursor.execute(
                        "INSERT INTO terapeutas (Nombre, Especialidad, Correo, Clave) VALUES (%s, %s, %s, %s)",
                        (nombre, especialidad, correo, clave_hash)
                    )
                    conn.commit()
                    flash("exito:Medico registrado correctamente.")
            else:
                flash("Completa todos los campos.")

        elif accion == "cambiar_clave":
            medico_id   = request.form.get("medico_id")
            nueva_clave = request.form.get("nueva_clave", "").strip()
            if medico_id and nueva_clave:
                clave_hash = bcrypt.generate_password_hash(nueva_clave).decode("utf-8")
                cursor.execute("UPDATE terapeutas SET Clave = %s WHERE ID = %s", (clave_hash, medico_id))
                conn.commit()
                flash("exito:Contrasena actualizada correctamente.")
            else:
                flash("Datos incompletos.")

        elif accion == "eliminar":
            medico_id = request.form.get("medico_id")
            if medico_id:
                cursor.execute("DELETE FROM terapeutas WHERE ID = %s", (medico_id,))
                conn.commit()
                flash("exito:Medico eliminado.")

        conn.close()
        return redirect(url_for("panel_admin"))

    cursor.execute("SELECT ID, Nombre, Especialidad, Correo FROM terapeutas ORDER BY Nombre ASC")
    medicos = cursor.fetchall()

    cursor.execute("""
        SELECT h.id, h.fecha_cita, h.estado,
               p.nombre, p.apellido, p.dni, p.telefono,
               t.Nombre AS terapeuta, t.Especialidad
        FROM historial_citas h
        JOIN personas p ON h.persona_id = p.id
        JOIN terapeutas t ON h.terapeuta_id = t.ID
        WHERE h.fecha_cita >= CURDATE()
        ORDER BY h.fecha_cita ASC
        LIMIT 20
    """)
    proximas_citas = cursor.fetchall()
    conn.close()

    return render_template("paneladmin.html", medicos=medicos, proximas_citas=proximas_citas)


@app.route("/panel_admin/cancelar_cita/<int:cita_id>", methods=["POST"])
@admin_required
def admin_cancelar_cita(cita_id):
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE historial_citas SET estado = 'cancelada' WHERE id = %s", (cita_id,))
    conn.commit()
    conn.close()
    flash("exito:Cita cancelada.")
    return redirect(url_for("panel_admin"))


# ═══════════════════════════════════════════════
# API REST  —  header requerido: X-API-Key
# ═══════════════════════════════════════════════

@app.route("/api/citas", methods=["GET"])
@api_key_required
def api_listar_citas():
    """GET /api/citas  ?dni=  ?fecha=YYYY-MM-DD  ?estado=programada"""
    dni    = request.args.get("dni", "")
    fecha  = request.args.get("fecha", "")
    estado = request.args.get("estado", "programada")

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    query  = """
        SELECT h.id, h.fecha_cita, h.estado,
               p.nombre, p.apellido, p.dni, p.telefono,
               t.Nombre AS terapeuta, t.Especialidad
        FROM historial_citas h
        JOIN personas p ON h.persona_id = p.id
        JOIN terapeutas t ON h.terapeuta_id = t.ID
        WHERE h.estado = %s
    """
    params = [estado]
    if dni:
        query += " AND p.dni = %s"
        params.append(dni)
    if fecha:
        query += " AND h.fecha_cita = %s"
        params.append(fecha)

    query += " ORDER BY h.fecha_cita ASC"
    cursor.execute(query, params)
    citas = cursor.fetchall()
    conn.close()

    for c in citas:
        if hasattr(c["fecha_cita"], "strftime"):
            c["fecha_cita"] = c["fecha_cita"].strftime("%Y-%m-%d")

    return jsonify({"success": True, "total": len(citas), "citas": citas})


@app.route("/api/citas/<int:cita_id>", methods=["GET"])
@api_key_required
def api_detalle_cita(cita_id):
    """GET /api/citas/{id}"""
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT h.id, h.fecha_cita, h.estado, h.descripcion,
               p.nombre, p.apellido, p.dni, p.telefono,
               t.Nombre AS terapeuta, t.Especialidad
        FROM historial_citas h
        JOIN personas p ON h.persona_id = p.id
        JOIN terapeutas t ON h.terapeuta_id = t.ID
        WHERE h.id = %s
    """, (cita_id,))
    cita = cursor.fetchone()
    conn.close()

    if not cita:
        return jsonify({"error": "Cita no encontrada"}), 404

    if hasattr(cita["fecha_cita"], "strftime"):
        cita["fecha_cita"] = cita["fecha_cita"].strftime("%Y-%m-%d")

    return jsonify({"success": True, "cita": cita})


@app.route("/api/citas", methods=["POST"])
@api_key_required
def api_crear_cita():
    """POST /api/citas — { nombre, apellido, dni, telefono, medico_id, fecha_cita }"""
    data = request.get_json() or {}

    for campo in ["nombre", "apellido", "dni", "telefono", "medico_id", "fecha_cita"]:
        if not data.get(campo):
            return jsonify({"error": f"Campo requerido: {campo}"}), 400

    try:
        fecha_obj = datetime.strptime(data["fecha_cita"], "%Y-%m-%d").date()
        if fecha_obj < datetime.today().date():
            return jsonify({"error": "La fecha no puede ser en el pasado"}), 400
    except ValueError:
        return jsonify({"error": "Formato de fecha invalido. Usa YYYY-MM-DD"}), 400

    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id FROM personas WHERE dni = %s", (data["dni"],))
    persona = cursor.fetchone()

    if persona:
        persona_id = persona["id"]
    else:
        cursor.execute(
            "INSERT INTO personas (nombre, apellido, dni, telefono) VALUES (%s, %s, %s, %s)",
            (data["nombre"], data["apellido"], data["dni"], data["telefono"])
        )
        conn.commit()
        persona_id = cursor.lastrowid

    cursor.execute(
        "INSERT INTO historial_citas (persona_id, terapeuta_id, fecha_cita, estado) VALUES (%s, %s, %s, 'programada')",
        (persona_id, data["medico_id"], data["fecha_cita"])
    )
    conn.commit()
    cita_id = cursor.lastrowid
    conn.close()

    return jsonify({"success": True, "cita_id": cita_id, "mensaje": "Cita creada correctamente"}), 201


@app.route("/api/citas/<int:cita_id>", methods=["PUT"])
@api_key_required
def api_modificar_cita(cita_id):
    """PUT /api/citas/{id} — { fecha_cita, medico_id }"""
    data         = request.get_json() or {}
    nueva_fecha  = data.get("fecha_cita", "")
    nuevo_medico = data.get("medico_id", "")

    if not nueva_fecha or not nuevo_medico:
        return jsonify({"error": "Se requieren fecha_cita y medico_id"}), 400

    try:
        fecha_obj = datetime.strptime(nueva_fecha, "%Y-%m-%d").date()
        if fecha_obj < datetime.today().date():
            return jsonify({"error": "La fecha no puede ser en el pasado"}), 400
    except ValueError:
        return jsonify({"error": "Formato invalido. Usa YYYY-MM-DD"}), 400

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE historial_citas SET fecha_cita = %s, terapeuta_id = %s WHERE id = %s AND estado = 'programada'",
        (nueva_fecha, nuevo_medico, cita_id)
    )
    conn.commit()
    afectadas = cursor.rowcount
    conn.close()

    if afectadas == 0:
        return jsonify({"error": "Cita no encontrada o ya no esta programada"}), 404

    return jsonify({"success": True, "mensaje": "Cita modificada correctamente"})


@app.route("/api/citas/<int:cita_id>", methods=["DELETE"])
@api_key_required
def api_cancelar_cita(cita_id):
    """DELETE /api/citas/{id}"""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE historial_citas SET estado = 'cancelada' WHERE id = %s AND estado = 'programada'",
        (cita_id,)
    )
    conn.commit()
    afectadas = cursor.rowcount
    conn.close()

    if afectadas == 0:
        return jsonify({"error": "Cita no encontrada o ya no esta programada"}), 404

    return jsonify({"success": True, "mensaje": "Cita cancelada correctamente"})


@app.route("/api/terapeutas", methods=["GET"])
@api_key_required
def api_terapeutas():
    """GET /api/terapeutas"""
    conn   = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT ID, Nombre, Especialidad FROM terapeutas ORDER BY Nombre ASC")
    terapeutas = cursor.fetchall()
    conn.close()
    return jsonify({"success": True, "terapeutas": terapeutas})


if __name__ == "__main__":
    app.run(debug=True)
