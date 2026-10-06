
import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="Banco Refassil | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# DATA — based on the project's established evidence
# ============================================================
TARGET = "142.93.12.42:8081"

own_services = pd.DataFrame([
    ["22/tcp", "SSH", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.17", "Activo"],
    ["25/tcp", "tcpwrapped", "tcpwrapped", "Activo"],
    ["3306/tcp", "MySQL", "MySQL 8.0.46", "Activo"],
    ["5000/tcp", "HTTP", "Werkzeug 3.0.1 / Python 3.11.16", "Activo"],
    ["8081/tcp", "HTTP", "nginx 1.31.6", "Activo"],
], columns=["Puerto", "Servicio", "Versión", "Estado"])

reference_services = pd.DataFrame([
    ["21/tcp", "FTP", "vsftpd 2.3.4", "CVE-2011-2523"],
    ["22/tcp", "SSH", "OpenSSH 7.2p2", "CVE-2016-6210"],
    ["80/tcp", "HTTP", "Apache 2.4.18", "CVE-2019-10098"],
    ["139/tcp", "NetBIOS", "Samba 3.0.20", "—"],
    ["445/tcp", "SMB", "Windows 7 Professional 7601 SP1", "MS17-010"],
    ["3306/tcp", "MySQL", "MySQL 5.5.54", "CVE-2016-6662"],
    ["5432/tcp", "PostgreSQL", "PostgreSQL 9.3", "CVE-2015-3165"],
    ["8080/tcp", "HTTP", "Apache Tomcat 7.0.52", "CVE-2017-12617"],
], columns=["Puerto", "Servicio", "Versión", "Referencia"])

vulns = [
    {
        "rank": 1, "name": "MS17-010 / EternalBlue",
        "cve": "CVE-2017-0143 / CVE-2017-0144 / CVE-2017-0145",
        "port": "445/tcp", "severity": "Crítica", "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "Compromiso remoto de confidencialidad, integridad y disponibilidad del activo SMB vulnerable.",
        "mitigation": "Aplicar parches MS17-010; deshabilitar SMBv1; migrar a SMBv2/3; restringir 445/tcp cuando no sea necesario; revisar SMB signing.",
        "poc": "nmap -Pn -p445 --script smb-vuln-ms17-010 <IP>",
        "result": "La salida Nmap de referencia identifica 445/tcp como vulnerable a MS17-010/EternalBlue.",
        "basis": "Nmap de referencia incluido en la práctica.",
    },
    {
        "rank": 2, "name": "vsftpd 2.3.4 backdoor",
        "cve": "CVE-2011-2523", "port": "21/tcp",
        "severity": "Crítica*", "score": None,
        "vector": "Pendiente de verificación CVSS 3.1",
        "impact": "RCE asociada a la versión vulnerable; el escenario también indica FTP anónimo.",
        "mitigation": "Actualizar/reemplazar vsftpd; eliminar FTP anónimo si no es necesario; restringir 21/tcp; revisar cuentas y credenciales.",
        "poc": "nmap -Pn -p21 --script ftp-vsftpd-backdoor <IP>",
        "result": "La referencia identifica vsftpd 2.3.4 y CVE-2011-2523.",
        "basis": "Nmap de referencia incluido en la práctica.",
    },
    {
        "rank": 3, "name": "Apache Tomcat 7.0.52",
        "cve": "CVE-2017-12617", "port": "8080/tcp",
        "severity": "Alta*", "score": None,
        "vector": "Pendiente de verificación CVSS 3.1",
        "impact": "La práctica describe RCE asociada al servicio vulnerable y sus condiciones de configuración.",
        "mitigation": "Actualizar Tomcat; revisar HTTP PUT; restringir Manager; aplicar autenticación y controles de acceso; segmentar el servicio.",
        "poc": "nmap -Pn -p8080 --script http-vuln-cve2017-12617 <IP>",
        "result": "La referencia identifica Apache Tomcat 7.0.52 y CVE-2017-12617.",
        "basis": "Nmap de referencia incluido en la práctica.",
    },
    {
        "rank": 4, "name": "MySQL 5.5.54",
        "cve": "CVE-2016-6662", "port": "3306/tcp",
        "severity": "Crítica*", "score": 9.8,
        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impact": "La referencia indica posible escalada de privilegios; también menciona bypass de autenticación si root no tiene contraseña.",
        "mitigation": "Actualizar MySQL; proteger root; restringir 3306/tcp; aplicar mínimo privilegio; revisar configuración y privilegios.",
        "poc": "Documentar versión expuesta y realizar comprobaciones no destructivas. No ejecutar bypass ni escalada sobre el objetivo.",
        "result": "La referencia identifica MySQL 5.5.54 y CVE-2016-6662.",
        "basis": "Nmap de referencia + fuente CVE consultada; la fuente publica CVSS v3.0.",
    },
    {
        "rank": 5, "name": "OpenSSH 7.2p2",
        "cve": "CVE-2016-6210", "port": "22/tcp",
        "severity": "Media", "score": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "impact": "Divulgación de información mediante enumeración remota de usuarios basada en diferencias de tiempo.",
        "mitigation": "Actualizar OpenSSH; reforzar autenticación; reducir información observable; monitorizar intentos de enumeración.",
        "poc": "Realizar validación no destructiva y comparar respuestas; no ejecutar fuerza bruta.",
        "result": "La referencia identifica OpenSSH 7.2p2 y CVE-2016-6210.",
        "basis": "Nmap de referencia + fuente CVSS 3.1 consultada.",
    },
]

sev_order = {"Crítica": 4, "Crítica*": 4, "Alta": 3, "Alta*": 3, "Media": 2, "Baja": 1}
sev_counts = {"Crítica": 3, "Alta": 1, "Media": 1}

# ============================================================
# STYLE
# ============================================================
st.markdown("""
<style>
:root { --navy:#071426; --blue:#1769ff; --cyan:#16b8d4; }
.block-container {padding-top: 1.2rem; padding-bottom: 2rem;}
[data-testid="stSidebar"] {background: #071426;}
[data-testid="stSidebar"] * {color: #f3f6fb !important;}
.hero {
    padding: 28px 30px;
    border-radius: 18px;
    background: linear-gradient(135deg,#071426 0%,#102b50 55%,#145b8f 100%);
    color: white;
    margin-bottom: 18px;
    box-shadow: 0 10px 30px rgba(7,20,38,.16);
}
.hero h1 {font-size: 2.15rem; margin:0;}
.hero p {margin:.45rem 0 0; opacity:.82;}
.metric-card {
    border:1px solid #e6ebf2; border-radius:16px; padding:18px;
    background:#fff; min-height:125px; box-shadow:0 5px 18px rgba(20,30,50,.05);
}
.metric-label {font-size:.82rem;color:#64748b;font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
.metric-value {font-size:1.8rem;font-weight:800;color:#0f172a;margin-top:8px;}
.risk-critical {border-left:5px solid #dc2626;background:#fff7f7;padding:15px;border-radius:10px;}
.risk-high {border-left:5px solid #f59e0b;background:#fffbeb;padding:15px;border-radius:10px;}
.risk-medium {border-left:5px solid #eab308;background:#fefce8;padding:15px;border-radius:10px;}
.info-box {border-left:5px solid #2563eb;background:#eff6ff;padding:15px;border-radius:10px;}
.success-box {border-left:5px solid #16a34a;background:#f0fdf4;padding:15px;border-radius:10px;}
.footer {color:#64748b;font-size:.82rem;text-align:center;margin-top:30px;}
</style>
""", unsafe_allow_html=True)

def metric_card(label, value, note=""):
    st.markdown(
        f"""<div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div style="color:#64748b;font-size:.82rem;margin-top:7px;">{note}</div>
        </div>""",
        unsafe_allow_html=True,
    )

def severity_class(sev):
    s = sev.lower()
    if "crítica" in s: return "risk-critical"
    if "alta" in s: return "risk-high"
    return "risk-medium"

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("## 🛡️ REFASSIL")
    st.caption("Security Assessment Dashboard")
    st.divider()
    page = st.radio(
        "Módulos",
        [
            "Dashboard ejecutivo",
            "Reconocimiento Nmap",
            "TOP 5 vulnerabilidades",
            "TOP 1 — EternalBlue",
            "PoC y evidencias",
            "Plan de mitigación",
            "Metodología",
        ],
    )
    st.divider()
    st.markdown("**Objetivo autorizado**")
    st.code(TARGET)
    st.caption("Herramienta académica · modo informativo")
    st.divider()
    st.caption("Estado del proyecto")
    st.success("Reconocimiento documentado")

# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div class="hero">
<h1>Banco Refassil · Security Dashboard</h1>
<p>Análisis de Vulnerabilidades con IA · UPB · Evaluación académica de seguridad</p>
</div>
""", unsafe_allow_html=True)

# ============================================================
# DASHBOARD
# ============================================================
if page == "Dashboard ejecutivo":
    st.subheader("Vista ejecutiva")

    c1,c2,c3,c4 = st.columns(4)
    with c1: metric_card("Objetivo", "8081/tcp", "142.93.12.42")
    with c2: metric_card("Servicios detectados", "5", "Nmap propio")
    with c3: metric_card("TOP 5", "5", "Nmap de referencia")
    with c4: metric_card("Riesgo TOP 1", "9.8", "Crítico · CVSS 3.1")

    st.write("")
    left,right = st.columns([1.05,.95])

    with left:
        st.markdown("### Distribución de riesgo")
        chart_df = pd.DataFrame(
            {"Severidad":["Crítica","Alta","Media"],"Vulnerabilidades":[3,1,1]}
        ).set_index("Severidad")
        st.bar_chart(chart_df, height=310)
        st.caption("Distribución del TOP 5 según la clasificación documentada.")

    with right:
        st.markdown("### Prioridad inmediata")
        st.markdown("""
        <div class="risk-critical">
        <b>01 · MS17-010 / EternalBlue</b><br>
        CVSS 9.8 · Crítica · 445/tcp
        </div><br>
        <div class="risk-critical">
        <b>02 · vsftpd 2.3.4</b><br>
        CVE-2011-2523 · Crítica*
        </div><br>
        <div class="risk-high">
        <b>03 · Apache Tomcat 7.0.52</b><br>
        CVE-2017-12617 · Alta*
        </div>
        """, unsafe_allow_html=True)

    st.markdown("### Estado del reconocimiento propio")
    st.dataframe(own_services, use_container_width=True, hide_index=True)

    st.markdown("""
    <div class="info-box">
    <b>Lectura importante:</b> el Nmap propio del objetivo autorizado no mostró los puertos
    21, 445 ni 8080. El TOP 5 se presenta por separado porque la práctica solicita utilizar
    el Nmap de referencia para la clasificación de vulnerabilidades.
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# NMAP
# ============================================================
elif page == "Reconocimiento Nmap":
    st.subheader("Reconocimiento del objetivo autorizado")
    st.markdown(f"**Target:** `{TARGET}`")

    st.markdown("### Comando ejecutado")
    st.code("nmap -Pn -sV --top-ports 1000 142.93.12.42 -oN nmap_top1000.txt", language="bash")

    st.markdown("### Resultado propio")
    st.dataframe(own_services, use_container_width=True, hide_index=True)

    st.warning(
        "Nmap indicó un límite de retransmisiones alcanzado en algunos puertos. "
        "La salida es evidencia del reconocimiento realizado y no debe interpretarse "
        "como prueba absoluta de ausencia de servicios."
    )

    st.markdown("### Respuesta HTTP 8081")
    st.code("""HTTP/1.1 200 OK
Server: nginx/1.31.6
Content-Type: text/html
Content-Length: 1736
Connection: keep-alive
ETag: "6abc5920-6c8\"""", language="text")

    st.markdown("### Observación de `assets/config.js`")
    st.code("""const ENDPOINTS = {
  login: '/api/auth/login',
  transfer: '/api/cuenta/transferir',
  transactions: '/api/cuenta/transacciones',
  upload: '/api/upload/foto'
};

// TODO: Remover antes de subir a producción
// Cuenta de pruebas para QA: 12345678-9

// Fix: usuario temporal para testing - falvis@refasssil.com
""", language="javascript")

    st.info(
        "La observación anterior se presenta como exposición de información de configuración. "
        "No se le asigna una CVE/CVSS en esta herramienta."
    )

    st.markdown("### Nmap de referencia utilizado para el TOP 5")
    st.dataframe(reference_services, use_container_width=True, hide_index=True)

# ============================================================
# TOP 5
# ============================================================
elif page == "TOP 5 vulnerabilidades":
    st.subheader("TOP 5 · Fichas de vulnerabilidad")
    st.caption("Contenido basado en el Nmap de referencia suministrado para la práctica.")

    for v in vulns:
        label = f"#{v['rank']} · {v['name']} · {v['cve']}"
        with st.expander(label, expanded=(v["rank"] == 1)):
            a,b,c = st.columns(3)
            with a: metric_card("Severidad", v["severity"], v["port"])
            with b: metric_card("CVSS", str(v["score"]) if v["score"] else "Pendiente", "según dato disponible")
            with c: metric_card("Servicio", v["port"], v["cve"])

            st.markdown("**1. Nombre técnico / CVE**")
            st.write(f"{v['name']} — {v['cve']}")

            st.markdown("**2. Impacto**")
            st.write(v["impact"])

            st.markdown("**3. CVSS 3.1 / vector**")
            st.code(v["vector"])

            st.markdown("**4. Mitigación**")
            st.write(v["mitigation"])

            st.markdown("**5. PoC / detección**")
            st.code(v["poc"], language="bash")
            st.write(v["result"])

            st.caption("Base: " + v["basis"])

# ============================================================
# TOP 1
# ============================================================
elif page == "TOP 1 — EternalBlue":
    v = vulns[0]
    st.subheader("TOP 1 · MS17-010 / EternalBlue")

    a,b,c = st.columns(3)
    with a: metric_card("CVSS 3.1", "9.8", "Crítica")
    with b: metric_card("Vector", "AV:N", "AC:L · PR:N · UI:N")
    with c: metric_card("Impacto", "C:H / I:H / A:H", "Scope: Unchanged")

    st.markdown("### Ficha técnica")
    st.markdown(f"**CVE:** {v['cve']}  \n**Servicio:** {v['port']}")
    st.markdown(f"**Impacto:** {v['impact']}")

    st.markdown("### Vector CVSS 3.1")
    st.code(v["vector"])
    st.success("9.8 · CRÍTICA")

    st.markdown("### Mitigación")
    st.write(v["mitigation"])

    st.markdown("### PoC de detección no destructiva")
    st.code(v["poc"], language="bash")
    st.write(v["result"])

    st.markdown("""
    <div class="info-box">
    Para la entrega, incorpora una captura real del resultado autorizado.
    La aplicación no fabrica ni simula evidencia.
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# EVIDENCE
# ============================================================
elif page == "PoC y evidencias":
    st.subheader("Centro de evidencias")
    st.caption("Carga aquí las capturas reales que acompañarán tu entrega.")

    st.markdown("""
    <div class="info-box">
    <b>Recomendación:</b> utiliza nombres claros como
    <code>01_nmap_target.png</code>, <code>02_eternalblue.png</code>,
    <code>03_vsftpd.png</code>, etc.
    </div>
    """, unsafe_allow_html=True)

    uploads = st.file_uploader(
        "Cargar capturas de evidencia",
        type=["png","jpg","jpeg","webp"],
        accept_multiple_files=True,
        help="Las imágenes quedan disponibles durante la sesión de la aplicación.",
    )

    if uploads:
        st.success(f"{len(uploads)} evidencia(s) cargada(s).")
        for idx, file in enumerate(uploads, 1):
            with st.expander(f"Evidencia {idx} · {file.name}", expanded=(idx == 1)):
                st.image(file, caption=file.name, use_container_width=True)

    st.divider()
    st.markdown("### Checklist de entrega")
    checks = [
        "Nmap del objetivo autorizado 142.93.12.42:8081",
        "Evidencia HTTP de 8081",
        "TOP 1 · detección MS17-010/EternalBlue",
        "PoC/detección de las vulnerabilidades restantes cuando corresponda",
        "Capturas reales, legibles y con comando + resultado",
        "Link público de la herramienta Streamlit",
    ]
    for item in checks:
        st.checkbox(item, key="check_" + item)

    st.markdown("### Comandos documentados")
    for v in vulns:
        st.markdown(f"**{v['rank']}. {v['name']}**")
        st.code(v["poc"], language="bash")

    st.warning(
        "No se deben adjuntar capturas fabricadas. Si una PoC no fue ejecutada sobre el "
        "laboratorio autorizado, presenta el comando como procedimiento sugerido y declara "
        "que no se ejecutó."
    )

# ============================================================
# MITIGATION
# ============================================================
elif page == "Plan de mitigación":
    st.subheader("Plan de remediación")

    priorities = [
        ("P1", "MS17-010 / EternalBlue", "Crítica", "Aplicar parches, deshabilitar SMBv1 y restringir 445/tcp."),
        ("P1", "vsftpd 2.3.4", "Crítica*", "Actualizar/reemplazar y eliminar FTP anónimo si no es necesario."),
        ("P1", "MySQL 5.5.54", "Crítica*", "Actualizar, proteger root y restringir 3306/tcp."),
        ("P2", "Apache Tomcat 7.0.52", "Alta*", "Actualizar, revisar HTTP PUT y restringir Manager."),
        ("P3", "OpenSSH 7.2p2", "Media", "Actualizar y reforzar controles de autenticación."),
    ]
    df = pd.DataFrame(priorities, columns=["Prioridad","Vulnerabilidad","Riesgo","Acción principal"])
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("### Acciones recomendadas")
    for p, name, risk, action in priorities:
        cls = severity_class(risk)
        st.markdown(
            f'<div class="{cls}"><b>{p} · {name}</b><br>{action}</div><br>',
            unsafe_allow_html=True
        )

# ============================================================
# METHODOLOGY
# ============================================================
else:
    st.subheader("Metodología, alcance y trazabilidad")

    st.markdown("""
    ### Alcance autorizado
    El objetivo web autorizado por la práctica es `http://142.93.12.42:8081`.

    ### Reconocimiento propio
    Se realizó Nmap con detección de servicios y consultas HTTP GET/HEAD no destructivas.

    ### Análisis de vulnerabilidades
    El TOP 5 se construye con el Nmap de referencia incluido en el enunciado, no
    sustituyéndolo por el Nmap propio del objetivo.

    ### Seguridad
    La herramienta no incorpora explotación, fuerza bruta, transferencia de dinero,
    carga de archivos, bypass de autenticación ni acciones destructivas.
    """)

    st.markdown("### Trazabilidad")
    st.dataframe(reference_services, use_container_width=True, hide_index=True)

    st.markdown("""
    <div class="success-box">
    <b>Estado:</b> dashboard listo para publicación académica.
    Antes de entregar, agrega las capturas reales y completa cualquier CVSS que aún figure
    como pendiente de verificación.
    </div>
    """, unsafe_allow_html=True)

st.markdown('<div class="footer">Banco Refassil S.A. · Análisis de Vulnerabilidades con IA · Proyecto académico UPB</div>', unsafe_allow_html=True)
