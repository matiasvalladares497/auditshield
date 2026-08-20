# Manual de Usuario — AuditShield
## Guía Completa para Auditorías de Ciberseguridad

---

> **Para quién es este manual:** Este manual está diseñado para estudiantes y docentes de liceos técnicos y usuarios sin experiencia previa en ciberseguridad avanzada. Explica paso a paso cómo usar AuditShield de forma segura y efectiva.

---

## Tabla de Contenidos

1. [¿Qué es AuditShield?](#1-qué-es-auditshield)
2. [Conceptos básicos de seguridad](#2-conceptos-básicos-de-seguridad)
3. [Primeros pasos: Crear tu cuenta](#3-primeros-pasos-crear-tu-cuenta)
4. [El Dashboard: Tu centro de control](#4-el-dashboard-tu-centro-de-control)
5. [Gestión de Assets (Activos)](#5-gestión-de-assets-activos)
6. [Realizar una auditoría](#6-realizar-una-auditoría)
7. [Interpretar los resultados](#7-interpretar-los-resultados)
8. [Los reportes PDF](#8-los-reportes-pdf)
9. [Glosario de términos](#9-glosario-de-términos)
10. [Preguntas frecuentes](#10-preguntas-frecuentes)
11. [Ética y uso responsable](#11-ética-y-uso-responsable)

---

## 1. ¿Qué es AuditShield?

**AuditShield** es una herramienta que permite revisar automáticamente la seguridad de sistemas informáticos como sitios web, servidores y redes. Es como un "médico" para tus sistemas: los examina, encuentra problemas y te dice cómo solucionarlos.

### ¿Para qué sirve?

| Puedes hacer... | Ejemplo |
|----------------|---------|
| Revisar si un sitio web tiene vulnerabilidades | Analizar el portal web del liceo |
| Verificar si un servidor está bien configurado | Revisar el servidor de la red interna |
| Generar reportes profesionales | Informe para la dirección del establecimiento |
| Monitorear la seguridad a lo largo del tiempo | Comparar resultados mes a mes |

### ¿Qué NO es AuditShield?

- ❌ No es un antivirus
- ❌ No es una herramienta para "hackear" sistemas ajenos
- ❌ No reemplaza a un especialista en seguridad para casos críticos
- ✅ Es una herramienta de **diagnóstico y análisis**

---

## 2. Conceptos básicos de seguridad

Antes de usar AuditShield, es útil entender algunos conceptos:

### Severidad de vulnerabilidades

| Nivel | Color | ¿Qué significa? |
|-------|-------|----------------|
| **CRÍTICO** | 🔴 Rojo | Vulnerabilidad grave que puede ser explotada de inmediato. Requiere acción urgente |
| **ALTO** | 🟠 Naranja | Problema serio que representa un riesgo significativo. Solucionar pronto |
| **MEDIO** | 🟡 Amarillo | Vulnerabilidad que podría ser explotada en ciertas condiciones. Planificar solución |
| **BAJO** | 🔵 Azul | Riesgo menor o teórico. Solucionar cuando sea posible |
| **INFO** | ⚪ Gris | Información útil, no es una vulnerabilidad propiamente |

### El Score de Seguridad

AuditShield calcula un puntaje de 0 a 100 para cada sistema auditado:

| Puntaje | Letra | Estado |
|---------|-------|--------|
| 90 – 100 | **A+** | Excelente — Seguridad muy sólida |
| 80 – 89 | **A** | Muy bueno — Seguridad sólida |
| 70 – 79 | **B** | Bueno — Algunas mejoras necesarias |
| 60 – 69 | **C** | Regular — Requiere trabajo de mejora |
| 50 – 59 | **D** | Deficiente — Problemas serios de seguridad |
| 0 – 49 | **F** | Crítico — Sistema en riesgo alto |

### ¿Qué es un "target"?

El **target** es el sistema que vas a auditar. Puede ser:

| Tipo | Ejemplo |
|------|---------|
| **Dominio** | `mipagina.cl` o `www.liceo.edu` |
| **URL** | `https://www.pagina.cl` |
| **Dirección IP** | `192.168.1.10` |
| **Rango de red** | `192.168.1.0/24` |

---

## 3. Primeros pasos: Crear tu cuenta

### Paso 1: Registrarse

1. Abre tu navegador y ve a `http://localhost:3000` (o la dirección que te indique tu administrador)
2. Haz clic en **"Crear cuenta"** en la página de login
3. Completa el formulario:
   - **Nombre completo**: Tu nombre y apellido
   - **Correo electrónico**: Tu correo institucional
   - **Usuario**: Un nombre corto sin espacios (ej: `jgonzalez`)
   - **Contraseña**: Mínimo 8 caracteres, usa mayúsculas, números y símbolos
4. Haz clic en **"Crear cuenta"**

> 💡 **Consejo:** Usa una contraseña fuerte. Combina letras mayúsculas y minúsculas, números y símbolos (ej: `Segur!dad2024`).

### Paso 2: Iniciar sesión

1. Ingresa tu correo y contraseña
2. Haz clic en **"Iniciar Sesión"**
3. Si las credenciales son correctas, serás redirigido al Dashboard

---

## 4. El Dashboard: Tu centro de control

Al iniciar sesión, verás el Dashboard principal. Tiene 4 secciones principales:

### Panel Superior — Estadísticas

Muestra de un vistazo el estado general de tus auditorías:

| Indicador | ¿Qué muestra? |
|-----------|--------------|
| **Total Auditorías** | Cuántas auditorías has realizado |
| **Vulnerabilidades Críticas** | Total de problemas críticos encontrados |
| **Score Promedio** | Calificación promedio de todos tus sistemas |
| **Assets Registrados** | Cuántos sistemas tienes registrados |

### Tabla de Auditorías Recientes

Muestra tus últimas auditorías con:
- **Target**: El sistema auditado
- **Score**: Calificación obtenida (con color verde/amarillo/rojo)
- **Estado**: Si está en progreso, completada o falló
- **Fecha**: Cuándo se realizó
- **Ver Detalle**: Botón para ver el análisis completo

### Gráfico de Vulnerabilidades

Muestra un gráfico de barras con la distribución de vulnerabilidades encontradas, separadas por severidad.

---

## 5. Gestión de Assets (Activos)

Un **asset** (activo) es un sistema que monitoreas regularmente. Registrar assets te permite:
- Ver el historial de auditorías de un sistema
- Comparar la seguridad a lo largo del tiempo
- Organizar mejor tus análisis

### Agregar un nuevo Asset

1. Haz clic en **"Assets"** en el menú lateral izquierdo
2. Haz clic en **"Agregar Asset"**
3. Completa la información:
   - **Nombre**: Un nombre descriptivo (ej: "Portal Web del Liceo")
   - **Target**: La URL, dominio o IP del sistema
   - **Tipo**: Selecciona el tipo (Dominio, IP, Aplicación Web, Red)
   - **Descripción**: Notas adicionales (opcional)
4. Haz clic en **"Guardar"**

### Ver historial de un Asset

Haz clic en el nombre de cualquier asset para ver:
- Todas las auditorías realizadas sobre ese sistema
- La evolución del score de seguridad en el tiempo
- Los cambios más recientes detectados

---

## 6. Realizar una auditoría

### Paso 1: Iniciar el asistente

Hay dos formas de iniciar una auditoría:
- Haz clic en **"Nueva Auditoría"** en el menú lateral, o
- Haz clic en el botón **"Nueva Auditoría"** en la barra superior

### Paso 2: Definir el objetivo

En este paso defines **qué** vas a auditar:

| Campo | ¿Qué poner? | Ejemplo |
|-------|------------|---------|
| **Target** | El sistema a auditar | `www.miliceo.cl` |
| **Título** | Un nombre para identificar esta auditoría | "Auditoría Portal Web Junio 2024" |
| **Tipo de Target** | El tipo de lo que estás auditando | Dominio |

> ⚠️ **IMPORTANTE**: Solo ingresa sistemas que tienes autorización de auditar. Ver [Sección 11 — Ética y uso responsable](#11-ética-y-uso-responsable).

Haz clic en **"Siguiente"**.

### Paso 3: Seleccionar el perfil de escaneo

Elige qué tipo de análisis quieres hacer:

| Perfil | Tiempo estimado | Ideal para... |
|--------|----------------|--------------|
| **Básico** | 2-5 min | Primera revisión rápida, IP internas |
| **Web App** | 5-15 min | Sitios y aplicaciones web |
| **Infraestructura** | 10-20 min | Servidores y redes |
| **Completo** | 15-40 min | Auditoría completa de todos los aspectos |
| **Personalizado** | Variable | Cuando sabes exactamente qué quieres revisar |

#### Módulos disponibles (en modo Personalizado)

| Módulo | ¿Qué revisa? |
|--------|-------------|
| **OSINT / Reconocimiento** | Información pública del dominio (WHOIS, DNS, subdominios) |
| **Escaneo de Puertos** | Qué puertos y servicios están abiertos en el servidor |
| **Análisis SSL/TLS** | Si el certificado HTTPS es válido y seguro |
| **Auditoría Web (OWASP)** | Los 10 problemas más comunes en páginas web |
| **Seguridad DNS** | Configuración de registros de correo (SPF, DKIM, DMARC) |
| **Exposición de Información** | Archivos sensibles expuestos (`.env`, `.git`, etc.) |
| **Matching de CVEs** | Vulnerabilidades conocidas en las tecnologías detectadas |
| **Detección WAF** | Si hay un firewall de aplicación web |
| **Cumplimiento Normativo** | Revisión contra OWASP ASVS y NIST CSF |

Haz clic en **"Siguiente"**.

### Paso 4: Opciones avanzadas

| Opción | Descripción | Recomendación para principiantes |
|--------|-------------|----------------------------------|
| **Intensidad** | Qué tan agresivo es el escaneo | Usar "Normal" |
| **Rango de puertos** | Qué puertos revisar | Dejar en `1-1000` |
| **Generar PDF automáticamente** | Crear reporte al terminar | Activar |
| **Notas** | Observaciones sobre la auditoría | Opcional |

Haz clic en **"Siguiente"**.

### Paso 5: Confirmación y lanzamiento

Revisa el resumen de la configuración. Si todo está correcto, haz clic en:

**🚀 Lanzar Auditoría**

Serás redirigido automáticamente a la página de progreso de la auditoría.

### Paso 6: Monitorear el progreso

Verás en tiempo real:
- **Terminal de logs**: Los pasos que está ejecutando el sistema
- **Módulos**: Cuáles ya terminaron (✅) y cuál está en progreso (⏳)
- **Tiempo transcurrido**: Cuánto tiempo lleva el escaneo

> ⏰ La auditoría puede tardar entre 2 y 40 minutos según el perfil seleccionado y la velocidad de respuesta del sistema objetivo.

---

## 7. Interpretar los resultados

### El Score de Seguridad

Al finalizar la auditoría, verás un círculo grande con el score. Por ejemplo:

```
       ████
      █    █
     █  A+  █
      █    █
       ████
        95
```

Un score de **95 con letra A+** significa que el sistema tiene muy buena seguridad.

### Los Hallazgos (Findings)

Cada "hallazgo" es un problema de seguridad encontrado. Para cada uno verás:

| Campo | Descripción |
|-------|-------------|
| **ID** | Identificador único (ej: AS-2024-001) |
| **Título** | Nombre del problema |
| **Severidad** | Qué tan grave es |
| **Módulo** | Qué módulo lo encontró |
| **Descripción** | Explicación del problema |
| **Evidencia** | Prueba técnica del problema |
| **Impacto** | Qué podría pasar si no se soluciona |
| **Recomendación** | Cómo solucionarlo |
| **Referencias** | Links a documentación oficial |

### Cómo leer un hallazgo — Ejemplo práctico

**Hallazgo**: Header de Seguridad CSP Faltante

- **Severidad**: Media 🟡
- **Descripción**: El sitio web no tiene el header `Content-Security-Policy`, lo que permite ataques XSS
- **Evidencia**: `GET https://ejemplo.cl/ → Header CSP: no presente`
- **Impacto**: Un atacante podría inyectar código malicioso en la página que afecte a los visitantes
- **Recomendación**: Agregar el header HTTP `Content-Security-Policy: default-src 'self'` en la configuración del servidor web
- **Referencia**: https://developer.mozilla.org/es/docs/Web/HTTP/CSP

### Filtrar y buscar hallazgos

Usa los filtros para encontrar lo que te interesa:
- **Por severidad**: Ver solo los críticos o altos
- **Por módulo**: Ver solo los problemas de SSL, por ejemplo
- **Búsqueda**: Buscar por nombre del hallazgo

### Marcar hallazgos

Puedes marcar cada hallazgo como:
- **Falso Positivo**: Si crees que es un error del escáner
- **Remediado**: Cuando ya solucionaste el problema

---

## 8. Los reportes PDF

### Generar un reporte

1. Ve a la página de detalle de una auditoría completada
2. Haz clic en **"Generar Reporte PDF"**
3. Selecciona el tipo de reporte:
   - **Ejecutivo**: Para presentar a directivos (sin detalles técnicos)
   - **Técnico**: Para el equipo IT (con evidencia y pasos de remediación)
   - **Completo**: Combina ambos
4. Haz clic en **"Generar"**
5. Espera unos segundos mientras se crea el PDF
6. Haz clic en **"Descargar PDF"**

### Tipos de reporte — ¿Cuál usar?

| Situación | Tipo recomendado |
|-----------|-----------------|
| Presentar resultados a la dirección del liceo | **Ejecutivo** |
| Entregarlo al equipo técnico para que solucione | **Técnico** |
| Auditoría formal para documentación | **Completo** |
| Proyecto de título / informe académico | **Completo** |

### ¿Qué incluye el reporte?

**Reporte Ejecutivo:**
- Portada con datos del cliente y fecha
- Resumen ejecutivo con score y clasificación
- Gráficos de distribución de riesgos
- Top 5 hallazgos más críticos
- Recomendaciones generales

**Reporte Técnico / Completo:**
- Todo lo anterior +
- Detalle completo de cada hallazgo
- Evidencia técnica
- Pasos específicos de remediación
- Referencias a estándares y CVEs
- Cumplimiento con normativas (OWASP, NIST)

---

## 9. Glosario de términos

| Término | Definición |
|---------|-----------|
| **Asset** | Un sistema informático que monitoreas (sitio web, servidor, etc.) |
| **Auditoría** | Análisis de seguridad de un sistema |
| **Banner Grabbing** | Técnica para identificar qué software usa un servidor |
| **CORS** | Cross-Origin Resource Sharing — cómo un sitio controla qué otros sitios pueden acceder a él |
| **CSP** | Content Security Policy — regla que controla qué scripts puede cargar una página |
| **CVE** | Common Vulnerabilities and Exposures — identificador estándar para vulnerabilidades conocidas |
| **CVSS** | Sistema de puntuación de severidad de vulnerabilidades (0-10) |
| **DKIM** | DomainKeys Identified Mail — firma digital para correos |
| **DMARC** | Domain-based Message Authentication — política anti-spam y anti-phishing |
| **DNSSEC** | Extensión de seguridad para el DNS |
| **Finding** | Hallazgo de seguridad encontrado durante una auditoría |
| **HSTS** | HTTP Strict Transport Security — fuerza el uso de HTTPS |
| **Nmap** | Herramienta de escaneo de puertos de red |
| **OSINT** | Open Source Intelligence — información obtenible de fuentes públicas |
| **OWASP** | Open Web Application Security Project — organización que define estándares de seguridad web |
| **Port** | Puerto de red (ej: 80 para HTTP, 443 para HTTPS) |
| **Score** | Puntuación de seguridad de 0 a 100 |
| **SPF** | Sender Policy Framework — registro que indica qué servidores pueden enviar correos |
| **SSL/TLS** | Protocolo de cifrado para comunicaciones seguras (HTTPS) |
| **Target** | El sistema objetivo de la auditoría |
| **Vulnerabilidad** | Debilidad en un sistema que puede ser explotada por un atacante |
| **WAF** | Web Application Firewall — cortafuegos para aplicaciones web |
| **WHOIS** | Base de datos que registra a quién pertenece un dominio |
| **XSS** | Cross-Site Scripting — ataque que inyecta código en páginas web |
| **Zone Transfer** | Transferencia completa de registros DNS (peligroso si está mal configurado) |

---

## 10. Preguntas frecuentes

### ¿Por qué el escaneo tarda tanto?

El tiempo varía según:
- **El perfil de escaneo**: Básico es rápido, Completo es lento
- **La velocidad de respuesta del target**: Servidores lentos hacen lentas las pruebas
- **Los módulos activados**: Cada módulo agrega tiempo
- **La disponibilidad de APIs externas**: El módulo CVE consulta APIs de internet

### ¿Puedo pausar o cancelar una auditoría?

Sí. En la página de detalle de la auditoría, mientras esté en progreso, verás un botón **"Cancelar Auditoría"**.

### ¿Los resultados son 100% precisos?

No necesariamente. Los escáneres automáticos pueden generar:
- **Falsos positivos**: Reportar un problema que en realidad no existe
- **Falsos negativos**: No detectar un problema que sí existe

AuditShield es una herramienta de apoyo. Los resultados siempre deben ser revisados por una persona.

### ¿Qué hago si encuentro un hallazgo crítico?

1. **No entrar en pánico**: Leer bien la descripción del hallazgo
2. **Entender el impacto**: ¿Qué podría pasar si no se soluciona?
3. **Consultar la recomendación**: AuditShield indica cómo solucionarlo
4. **Documentarlo**: Guardar el reporte PDF
5. **Informar al responsable técnico**: Compartir el reporte
6. **Verificar la solución**: Volver a auditar después de solucionar

### ¿Puedo auditar cualquier sitio web?

**No.** Solo puedes auditar sistemas para los cuales tienes autorización. Ver [Sección 11](#11-ética-y-uso-responsable).

### ¿Los datos de mis auditorías son privados?

Sí. AuditShield almacena los datos en tu propio servidor. No envía información a terceros (excepto al consultar APIs públicas como NVD para CVEs).

### ¿Necesito internet para usar AuditShield?

Para la mayoría de los módulos, sí necesitas internet. Algunos módulos que consultan APIs externas (CVE, OSINT) no funcionarán sin conexión. El módulo de puertos puede funcionar en redes locales sin internet.

### ¿Cómo agrego más usuarios?

Si tienes rol de **Administrador**, puedes ir a Configuración → Sistema → Usuarios y agregar nuevas cuentas.

---

## 11. Ética y uso responsable

### La regla de oro

> **Solo audita sistemas para los cuales tienes autorización expresa y por escrito.**

Usar herramientas de seguridad sin autorización es un **delito** en Chile (Ley N° 19.223 sobre Delitos Informáticos) y en la mayoría de los países.

### ¿Qué puedo auditar?

| ✅ SÍ está permitido | ❌ NO está permitido |
|---------------------|---------------------|
| Tu propio sitio web o servidor | Sitios de terceros sin permiso |
| Sistemas del liceo (con autorización del director) | Portales bancarios, del gobierno, etc. |
| Entornos de laboratorio/práctica | Redes de empresas sin autorización |
| Sistemas donde tienes contrato de auditoría | Sistemas de otras personas |

### Entornos de práctica seguros

Para aprender sin riesgos legales, puedes practicar con:

| Recurso | Descripción |
|---------|-------------|
| **DVWA** | Damn Vulnerable Web Application — app web vulnerable a propósito |
| **Metasploitable** | Máquina virtual vulnerable para practicar |
| **HackTheBox** | Plataforma de labs de seguridad (requiere cuenta) |
| **TryHackMe** | Plataforma educativa de seguridad |
| **Tu propia VM** | Monta tu propio servidor de práctica |

### Responsabilidad del auditor

Como auditor, eres responsable de:
1. **Obtener autorización**: Siempre por escrito, firmado por el responsable
2. **Proteger la información**: Los resultados de la auditoría son confidenciales
3. **Reportar correctamente**: Comunicar los hallazgos al responsable del sistema
4. **No explotar vulnerabilidades**: Encontrar ≠ explotar. Solo reportar
5. **Documentar todo**: Guardar evidencia de la autorización y los resultados

### Plantilla de autorización

Antes de cualquier auditoría en un sistema de terceros, solicita firma de una carta de autorización. Ejemplo:

```
AUTORIZACIÓN DE AUDITORÍA DE SEGURIDAD

Yo, [Nombre y cargo del responsable], RUT [XXX], 
en representación de [Nombre de la organización],
autorizo expresamente la realización de una auditoría 
de seguridad informática sobre los siguientes sistemas:

- [Lista de IPs, dominios o sistemas a auditar]

Esta autorización es válida desde el [fecha inicio] 
hasta el [fecha fin].

Nombre: ___________________
Cargo:  ___________________
Firma:  ___________________
Fecha:  ___________________
```

---

## Apéndice: Tabla de referencia rápida

### Perfis de escaneo recomendados por objetivo

| Objetivo | Perfil recomendado | Módulos clave |
|----------|-------------------|---------------|
| Revisar un sitio web del liceo | Web App | Web, SSL, Headers |
| Revisar el servidor de la red interna | Infraestructura | Puertos, Servicios |
| Auditoría completa para informe formal | Completo | Todos |
| Verificar rápido si hay algo urgente | Básico | OSINT, Puertos |
| Revisar el correo del dominio | Personalizado | DNS (SPF/DKIM/DMARC) |

### Tiempo estimado de auditoría

| Perfil | Tiempo típico |
|--------|--------------|
| Básico | 2 – 5 minutos |
| Web App | 5 – 15 minutos |
| Infraestructura | 10 – 20 minutos |
| Completo | 20 – 45 minutos |

### Qué significa cada letra del score

| Letra | Qué hacer |
|-------|-----------|
| A+ / A | ¡Excelente! Mantener así y revisar periódicamente |
| B | Resolver los problemas medios pendientes |
| C | Atención: hay problemas que necesitan solución |
| D | Urgente: múltiples problemas serios |
| F | Crítico: actuar inmediatamente |

---

*Manual de Usuario AuditShield v1.0 — Proyecto de Título, Ingeniería en Informática*

*Para soporte técnico, contactar al administrador del sistema.*
