# ☁️ Guía de Despliegue en la Nube 24/7 — AuditShield

Esta guía describe cómo desplegar **AuditShield** de forma **gratuita y permanente (24/7)** en la nube para que el liceo pueda acceder desde cualquier lugar del mundo.

---

## 🚀 Método Recomendado: Despliegue Automático en Render (1 Clic)

[Render.com](https://render.com) es una plataforma en la nube que permite desplegar bases de datos PostgreSQL, aplicaciones FastAPI y Next.js gratis.

### Pasos para desplegar:

#### Paso 1: Subir el proyecto a GitHub
1. Crea una cuenta gratuita en [GitHub](https://github.com).
2. Crea un repositorio público o privado llamado `auditshield`.
3. Sube la carpeta del proyecto a tu repositorio de GitHub:
   ```bash
   git init
   git add .
   git commit -m "Inicializar AuditShield para despliegue"
   git branch -M main
   git remote add origin https://github.com/TU_USUARIO/auditshield.git
   git push -u origin main
   ```

#### Paso 2: Crear el Blueprint en Render
1. Crea una cuenta gratuita en [Render.com](https://render.com).
2. En el panel principal, haz clic en **New +** y selecciona **Blueprint**.
3. Conecta tu cuenta de GitHub y selecciona el repositorio `auditshield`.
4. Render detectará automáticamente el archivo `render.yaml` que ya creamos en el proyecto.
5. Haz clic en **Apply**.

¡Listo! Render creará automáticamente:
* 🐘 Base de datos PostgreSQL administrada
* 🚀 Servicio Backend API (FastAPI)
* 🛡️ Servicio Frontend (Next.js)
* ⚙️ Workers de escaneo de seguridad

---

## ⚡ Método Alternativo 2: Vercel (Frontend) + Render (Backend)

Si prefieres una velocidad de carga ultra-rápida para la interfaz web:

1. **Frontend en Vercel:**
   - Inicia sesión en [Vercel.com](https://vercel.com) con GitHub.
   - Importa la carpeta `frontend`.
   - Agrega la variable de entorno `NEXT_PUBLIC_API_URL` apuntando al backend en Render (`https://auditshield-backend.onrender.com`).
   - Haz clic en **Deploy**.

2. **Backend en Render:**
   - Crea un **Web Service** seleccionando el directorio `backend`.
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

---

## 🔐 Credenciales Iniciales de Administrador

Una vez desplegada la aplicación en la nube, el primer usuario administrador para el liceo se crea mediante el formulario de registro (`/register`) o con las credenciales por defecto:

* **Email:** `admin@auditshield.io`
* **Contraseña:** `Admin1234!`
