<div align="center">

<img src="https://img.shields.io/badge/AuditShield-v1.0.0-6366F1?style=for-the-badge&logo=shield&logoColor=white" alt="AuditShield" />
<br/><br/>

# 🛡️ AuditShield

**Plataforma Profesional de Auditoría de Ciberseguridad**

*Proyecto de Título — Ingeniería en Informática*

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?style=flat-square&logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/Licencia-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📋 Tabla de Contenidos

- [Descripción](#-descripción)
- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Módulos de Escaneo](#-módulos-de-escaneo)
- [Requisitos](#-requisitos)
- [Instalación Rápida](#-instalación-rápida)
- [Uso](#-uso)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [API Reference](#-api-reference)
- [Reportes PDF](#-reportes-pdf)
- [Frameworks de Cumplimiento](#-frameworks-de-cumplimiento)
- [Contribuir](#-contribuir)

---

## 📖 Descripción

**AuditShield** es una plataforma completa de auditoría de ciberseguridad diseñada para ser utilizada por equipos de seguridad de todos los niveles, desde liceos técnicos hasta empresas grandes. Permite realizar auditorías automatizadas y profesionales de sistemas, páginas web, servidores e infraestructura de red.

La plataforma fue desarrollada como **Proyecto de Título de Ingeniería en Informática**, con el objetivo de proveer una herramienta open-source, en español, accesible y de nivel profesional.

---

## ✨ Características

### 🔍 Escaneo Multi-módulo
- **OSINT & Reconocimiento**: WHOIS, DNS, subdominios vía Certificate Transparency, geolocalización IP, fingerprinting de tecnologías
- **Análisis SSL/TLS**: Certificados, protocolos (SSLv2/v3, TLS 1.0-1.3), cipher suites débiles, HSTS, grade SSL
- **Web Application Security**: OWASP Top 10, headers de seguridad, métodos HTTP peligrosos, archivos expuestos, CORS, cookies, CSRF
- **Escaneo de Puertos**: nmap integrado, detección de servicios, banner grabbing, servicios peligrosos
- **Seguridad DNS**: SPF, DKIM, DMARC, DNSSEC, zone transfer, open resolvers
- **Detección WAF**: Identificación de firewalls de aplicación web (Cloudflare, ModSecurity, AWS WAF, etc.)
- **CVE Matching**: Búsqueda automática en NVD/NIST para tecnologías detectadas
- **Cumplimiento**: OWASP ASVS, NIST CSF, ISO 27001 (próximamente PCI DSS, CIS Controls)

### 📊 Dashboard & Visualización
- Puntuación de seguridad 0-100 con clasificación A+/A/B/C/D/F
- Gráficos de distribución de vulnerabilidades en tiempo real
- Historial de auditorías y evolución del score
- Gestión de assets (activos a auditar)

### 🔴 Tiempo Real
- Logs de escaneo en tiempo real via WebSocket
- Progreso por módulo con indicadores visuales
- Actualizaciones instantáneas de hallazgos mientras escanea

### 📄 Reportes PDF Profesionales
- **Reporte Ejecutivo**: Resumen para directivos y stakeholders no técnicos
- **Reporte Técnico**: Detalle completo para equipos de seguridad
- **Reporte de Cumplimiento**: Mapeo a frameworks normativos
- Gráficos SVG embebidos, evidencias, recomendaciones y referencias

---

## 🏗️ Arquitectura

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Next.js 14    │───▶│   FastAPI 0.111  │───▶│  PostgreSQL 15  │
│   (Frontend)    │    │   (Backend API)  │    │   (Base datos)  │
│   Puerto 3000   │    │   Puerto 8000    │    │   Puerto 5432   │
└─────────────────┘    └────────┬─────────┘    └─────────────────┘
         │                      │
         │ WebSocket             │ Pub/Sub
         │                      ▼
         │             ┌─────────────────┐
         └────────────▶│   Redis 7       │
                       │  (Cache/Queue)  │
                       │  Puerto 6379    │
                       └────────┬────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  Celery Worker  │
                       │ (Scan Engine)   │
                       └─────────────────┘
```

### Stack Tecnológico

| Capa | Tecnología |
|------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Zustand |
| Backend API | FastAPI, Python 3.11, SQLAlchemy 2.0 async |
| Base de Datos | PostgreSQL 15 |
| Cache/Queue | Redis 7 |
| Task Worker | Celery 5.4 |
| Contenedores | Docker + Docker Compose |
| Reportes | WeasyPrint, Jinja2, Matplotlib |
| Autenticación | JWT (RS256), bcrypt |

---

## 🔬 Módulos de Escaneo

| Módulo | Archivo | Descripción |
|--------|---------|-------------|
| OSINT | `scanners/osint.py` | Reconocimiento pasivo completo |
| SSL/TLS | `scanners/ssl_analyzer.py` | Análisis de certificados y protocolos |
| Web | `scanners/web_scanner.py` | OWASP Top 10 y headers de seguridad |
| DNS | `scanners/dns_auditor.py` | SPF, DKIM, DMARC, DNSSEC |
| Puertos | `scanners/port_scanner.py` | Nmap + banner grabbing |
| CVE | `scanners/cve_matcher.py` | Matching con base NVD/NIST |
| WAF | `scanners/waf_detector.py` | Detección de firewalls |
| Compliance | `scanners/compliance_checker.py` | OWASP ASVS + NIST CSF |

---

## ⚙️ Requisitos

### Software necesario

| Requisito | Versión mínima |
|-----------|---------------|
| Docker | 24.x |
| Docker Compose | 2.x |
| Node.js (dev) | 20.x |
| Python (dev) | 3.11+ |
| nmap | 7.x (en host para dev sin Docker) |

### Hardware recomendado

| Recurso | Mínimo | Recomendado |
|---------|--------|-------------|
| RAM | 4 GB | 8 GB |
| CPU | 2 cores | 4 cores |
| Disco | 10 GB | 20 GB |

---

## 🚀 Instalación Rápida

### Opción 1: Docker Compose (Recomendado)

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/auditshield.git
cd auditshield

# 2. Copiar y configurar variables de entorno
cp backend/.env.example backend/.env
# Editar backend/.env con tus valores

# 3. Levantar todos los servicios
docker compose up -d

# 4. Verificar que todo esté funcionando
docker compose ps
curl http://localhost:8000/health

# 5. Abrir el navegador
# http://localhost:3000
```

### Opción 2: Desarrollo Local

#### Backend
```bash
cd auditshield/backend

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Instalar dependencias
pip install -r requirements.txt

# Copiar variables de entorno
cp .env.example .env
# Editar .env con tu configuración

# Iniciar base de datos con Docker
docker run -d --name auditshield_db \
  -e POSTGRES_USER=auditshield \
  -e POSTGRES_PASSWORD=auditshield_secret \
  -e POSTGRES_DB=auditshield \
  -p 5432:5432 postgres:15-alpine

# Iniciar Redis con Docker
docker run -d --name auditshield_redis \
  -p 6379:6379 redis:7-alpine

# Iniciar el backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# En otra terminal: iniciar el worker Celery
celery -A app.workers.celery_app worker --loglevel=info
```

#### Frontend
```bash
cd auditshield/frontend

# Instalar dependencias
npm install

# Copiar variables de entorno
cp .env.local.example .env.local  # o crear manualmente

# Iniciar el frontend
npm run dev
# Abrir http://localhost:3000
```

---

## 🖥️ Uso

### 1. Crear una cuenta
Navega a `http://localhost:3000` y regístrate con tu correo y contraseña.

### 2. Agregar un asset
Ve a **Assets** en el menú lateral y agrega el dominio, IP o URL que quieres auditar.
> ⚠️ **Importante**: Solo audita sistemas que tengas autorización expresa para escanear.

### 3. Lanzar una auditoría
1. Haz clic en **Nueva Auditoría**
2. Ingresa el target (ej: `example.com` o `192.168.1.1`)
3. Selecciona el perfil de escaneo:
   - **Básico**: Solo reconocimiento y puertos
   - **Web App**: Enfocado en aplicaciones web (OWASP)
   - **Infraestructura**: Puertos, servicios y red
   - **Completo**: Todos los módulos
   - **Personalizado**: Elige módulos individuales
4. Configura opciones avanzadas si necesario
5. Haz clic en **Lanzar Auditoría**

### 4. Monitorear el progreso
La página de detalle mostrará un **terminal en vivo** con los logs del escaneo en tiempo real.

### 5. Revisar los resultados
Una vez completado, verás:
- **Score de seguridad** con clasificación por letra
- **Lista de hallazgos** filtrable por severidad
- **Detalle de cada vulnerabilidad** con evidencia y recomendación

### 6. Generar el reporte PDF
Haz clic en **Generar Reporte PDF** y elige el tipo:
- Ejecutivo (para dirección)
- Técnico (para equipos IT)
- Completo (todo incluido)

---

## 📁 Estructura del Proyecto

```
auditshield/
├── 📁 backend/
│   ├── 📄 Dockerfile
│   ├── 📄 requirements.txt
│   ├── 📄 .env.example
│   └── 📁 app/
│       ├── 📄 main.py              # Punto de entrada FastAPI
│       ├── 📁 api/                 # Endpoints REST
│       │   ├── auth.py             # Login, register, JWT
│       │   ├── audits.py           # Gestión de auditorías
│       │   ├── assets.py           # Gestión de activos
│       │   ├── reports.py          # Generación de PDFs
│       │   ├── users.py            # Administración de usuarios
│       │   └── websocket.py        # WebSocket para logs en vivo
│       ├── 📁 core/                # Configuración central
│       │   ├── config.py           # Variables de entorno
│       │   ├── database.py         # Conexión SQLAlchemy async
│       │   └── security.py         # JWT, bcrypt, tokens
│       ├── 📁 models/              # Modelos SQLAlchemy
│       │   ├── user.py             # Usuario, Organización, Rol
│       │   └── audit.py            # Auditoría, Finding, Report, Asset
│       ├── 📁 scanners/            # Módulos de escaneo
│       │   ├── osint.py            # WHOIS, DNS, subdomains
│       │   ├── ssl_analyzer.py     # SSL/TLS analysis
│       │   ├── web_scanner.py      # OWASP web checks
│       │   ├── dns_auditor.py      # SPF/DKIM/DMARC/DNSSEC
│       │   ├── port_scanner.py     # nmap + banner grabbing
│       │   ├── cve_matcher.py      # NVD API integration
│       │   ├── waf_detector.py     # WAF fingerprinting
│       │   └── compliance_checker.py # OWASP ASVS, NIST
│       ├── 📁 services/            # Lógica de negocio
│       │   ├── audit_engine.py     # Score, letter, summaries
│       │   └── report_engine.py    # Generación PDF WeasyPrint
│       └── 📁 workers/
│           └── celery_app.py       # Tasks asíncronas de escaneo
│
├── 📁 frontend/
│   ├── 📄 Dockerfile
│   ├── 📄 package.json
│   └── 📁 app/
│       ├── page.tsx                # Redirect según auth
│       ├── login/page.tsx          # Login page
│       ├── register/page.tsx       # Register page
│       ├── not-found.tsx           # 404 personalizado
│       └── dashboard/
│           ├── layout.tsx          # Layout con sidebar
│           ├── page.tsx            # Dashboard principal
│           ├── settings/page.tsx   # Configuración
│           ├── audits/
│           │   ├── new/page.tsx    # Wizard nueva auditoría
│           │   └── [id]/page.tsx   # Detalle + live logs
│           ├── assets/page.tsx     # Gestión de activos
│           └── reports/page.tsx    # Lista de reportes
│
├── 📁 reports/
│   ├── 📁 templates/
│   │   └── report_full.html        # Template HTML/CSS para PDF
│   └── 📁 assets/                  # PDFs generados
│
├── 📄 docker-compose.yml
└── 📄 README.md
```

---

## 📡 API Reference

La documentación interactiva está disponible en:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Endpoints principales

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Iniciar sesión |
| `POST` | `/api/auth/register` | Registrar usuario |
| `GET` | `/api/auth/me` | Perfil del usuario |
| `GET` | `/api/audits` | Listar auditorías |
| `POST` | `/api/audits` | Crear y lanzar auditoría |
| `GET` | `/api/audits/{id}` | Detalle de auditoría |
| `GET` | `/api/audits/{id}/findings` | Hallazgos de la auditoría |
| `GET` | `/api/assets` | Listar activos |
| `POST` | `/api/assets` | Crear activo |
| `POST` | `/api/reports/generate` | Generar PDF |
| `GET` | `/api/reports/{id}/download` | Descargar PDF |
| `WS` | `/ws/audit/{id}` | Stream de logs en tiempo real |

---

## 📄 Reportes PDF

AuditShield genera reportes profesionales en tres formatos:

### Reporte Ejecutivo (`executive`)
Ideal para presentar a directivos y stakeholders. Incluye:
- Resumen ejecutivo con score global
- Gráficos de distribución de riesgos
- Top 5 hallazgos más críticos
- Recomendaciones estratégicas

### Reporte Técnico (`technical`)
Para equipos de seguridad e IT. Incluye:
- Todos los hallazgos con evidencia técnica
- Detalles de configuración insegura
- Pasos de remediación específicos
- Referencias a CVEs y estándares

### Reporte Completo (`full`)
Combina ambos. Para auditorías formales.

---

## 📋 Frameworks de Cumplimiento

| Framework | Descripción | Estado |
|-----------|-------------|--------|
| OWASP Top 10 | 10 riesgos más críticos en aplicaciones web | ✅ Implementado |
| OWASP ASVS | Application Security Verification Standard | ✅ Implementado |
| NIST CSF | Cybersecurity Framework | ✅ Implementado |
| ISO 27001 | Sistema de Gestión de Seguridad | 🔄 Parcial |
| PCI DSS | Estándar de Seguridad de Datos de Tarjetas | 🔜 Próximamente |
| CIS Controls | Center for Internet Security Controls | 🔜 Próximamente |

---

## 🛠️ Desarrollo

### Ejecutar Tests

```bash
# Backend tests
cd backend
pip install pytest pytest-asyncio httpx
pytest tests/ -v

# Con cobertura
pytest tests/ --cov=app --cov-report=html
```

### Variables de entorno para desarrollo

```bash
# backend/.env
DATABASE_URL=postgresql+asyncpg://auditshield:auditshield_secret@localhost:5432/auditshield
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=tu-clave-secreta-muy-larga-y-aleatoria
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
ENVIRONMENT=development
```

---

## ⚠️ Consideraciones Éticas y Legales

> **IMPORTANTE**: AuditShield debe usarse ÚNICAMENTE en sistemas para los cuales tienes autorización expresa y por escrito.

- ✅ Usar en tus propios sistemas y redes
- ✅ Usar en sistemas de clientes con contrato de auditoría firmado
- ✅ Usar en entornos de laboratorio/prueba
- ❌ **PROHIBIDO** usar en sistemas sin autorización
- ❌ **PROHIBIDO** usar para actividades maliciosas

El uso indebido de esta herramienta puede constituir un delito informático según la legislación vigente.

---

## 📜 Licencia

Este proyecto está bajo la **Licencia MIT**. Ver [LICENSE](LICENSE) para más detalles.

---

## 👤 Autor

Desarrollado como **Proyecto de Título** de Ingeniería en Informática.

Herramienta donada al uso educativo para liceos técnicos y comunidad de ciberseguridad.

---

<div align="center">

**AuditShield** — *Auditoría de Ciberseguridad Profesional* 🛡️

*Hecho con ❤️ para la comunidad de seguridad informática hispanohablante*

</div>
