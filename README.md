# Banco Refassil — Security Dashboard

Dashboard profesional en Streamlit para la práctica académica "Análisis de Vulnerabilidades con IA".

## Ejecutar

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

En Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Publicar en Streamlit Community Cloud

1. Crear un repositorio público en GitHub.
2. Subir `app.py` y `requirements.txt`.
3. Entrar a Streamlit Community Cloud.
4. Seleccionar el repositorio.
5. Elegir `app.py` como Main file.
6. Publicar.

## Funciones

- Dashboard ejecutivo.
- Tarjetas de riesgo.
- Gráfico de distribución del TOP 5.
- Reconocimiento Nmap propio separado del Nmap de referencia.
- Fichas completas de TOP 5.
- Vista dedicada de EternalBlue.
- Centro de carga de capturas de evidencia.
- Checklist de entrega.
- Plan de mitigación.
- Metodología y trazabilidad.

La aplicación es informativa: no ejecuta exploits ni acciones ofensivas.
