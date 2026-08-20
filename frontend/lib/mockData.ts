// Datos de demostración y simulador para modo sin backend (Modo Demo)

export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string;
  role: string;
  created_at: string;
}

export interface Audit {
  id: number;
  title: string;
  target: string;
  target_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  profile: string;
  score: number | null;
  score_letter: string | null;
  security_score?: number | null; // support both score names
  created_at: string;
  completed_at: string | null;
  duration: number | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  progress: number;
  current_module: string | null;
  notes: string | null;
  options: Record<string, any>;
  modules?: string[] | Record<string, boolean>;
}

export interface Finding {
  id: number;
  audit_id: number;
  finding_id: string | null;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  module: string;
  cvss_score: number | null;
  cvss_vector?: string | null;
  cve_id: string | null;
  evidence: string | null;
  impact: string | null;
  recommendation: string | null;
  references: string[];
  status: 'open' | 'false_positive' | 'remediated';
  is_remediated?: boolean; // UI binding
  is_false_positive?: boolean; // UI binding
  created_at: string;
}

export interface Asset {
  id: number;
  name: string;
  target: string;
  asset_type: string;
  last_score: number | null;
  last_score_letter: string | null;
  last_audit_at?: string | null;
  last_audited?: string | null;
  created_at: string;
  description?: string | null;
  tags?: string[];
}

export interface Report {
  id: number;
  audit_id: number;
  audit_title: string;
  report_type: string;
  file_size: number | null;
  created_at: string;
  status: 'generating' | 'ready' | 'failed';
}

const DEMO_AUDITS: Audit[] = [
  {
    id: 1, title: 'Auditoría Portal Web', target: 'www.mipagina.cl', target_type: 'domain',
    status: 'completed', profile: 'full', score: 72, security_score: 72, score_letter: 'B',
    created_at: new Date(Date.now() - 2 * 86400000).toISOString(),
    completed_at: new Date(Date.now() - 2 * 86400000 + 45 * 60000).toISOString(),
    duration: 2700, findings_count: 4, progress: 100, current_module: 'Completado',
    critical_count: 1, high_count: 1, medium_count: 1, low_count: 1, info_count: 0,
    notes: 'Escaneo inicial del portal web de producción.',
    options: { intensity: 'normal', port_range: '1-1000', auto_report: true },
    modules: { osint: true, ssl: true, web: true, ports: true }
  },
  {
    id: 2, title: 'Revisión Servidor Linux', target: '192.168.1.10', target_type: 'ip',
    status: 'completed', profile: 'technical', score: 55, security_score: 55, score_letter: 'D',
    created_at: new Date(Date.now() - 5 * 86400000).toISOString(),
    completed_at: new Date(Date.now() - 5 * 86400000 + 12 * 60000).toISOString(),
    duration: 720, findings_count: 2, progress: 100, current_module: 'Completado',
    critical_count: 1, high_count: 1, medium_count: 0, low_count: 0, info_count: 0,
    notes: 'Escaneo de vulnerabilidades en servidor de base de datos interno.',
    options: { intensity: 'aggressive', port_range: '1-10000', auto_report: true },
    modules: { ports: true, ssl: true }
  },
  {
    id: 3, title: 'Scan Rápido DNS', target: 'liceo.edu.cl', target_type: 'domain',
    status: 'completed', profile: 'basic', score: 88, security_score: 88, score_letter: 'A',
    created_at: new Date(Date.now() - 1 * 86400000).toISOString(),
    completed_at: new Date(Date.now() - 1 * 86400000 + 5 * 60000).toISOString(),
    duration: 300, findings_count: 2, progress: 100, current_module: 'Completado',
    critical_count: 0, high_count: 0, medium_count: 2, low_count: 0, info_count: 0,
    notes: 'Revisión rápida de configuración DNS y correo electrónico institucional.',
    options: { intensity: 'stealth', port_range: '80,443', auto_report: false },
    modules: { dns: true, ssl: true }
  },
  {
    id: 4, title: 'Auditoría Completa ERP', target: 'erp.empresa.cl', target_type: 'domain',
    status: 'running', profile: 'full', score: null, security_score: null, score_letter: null,
    created_at: new Date(Date.now() - 15 * 60000).toISOString(),
    completed_at: null, duration: null, findings_count: 0, progress: 45, current_module: 'Escaneo de Puertos TCP',
    critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, info_count: 0,
    notes: 'Escaneo completo de la plataforma ERP institucional.',
    options: { intensity: 'normal', port_range: '1-1000', auto_report: true },
    modules: { osint: true, ssl: true, web: true, ports: true, dns: true }
  }
];

const DEMO_ASSETS: Asset[] = [
  { id: 1, name: 'Portal Web Liceo', target: 'www.liceo.edu.cl', asset_type: 'domain', last_score: 88, last_score_letter: 'A', last_audit_at: new Date(Date.now() - 1 * 86400000).toISOString(), created_at: new Date(Date.now() - 30 * 86400000).toISOString() },
  { id: 2, name: 'Servidor Interno', target: '192.168.1.10', asset_type: 'ip', last_score: 55, last_score_letter: 'D', last_audit_at: new Date(Date.now() - 5 * 86400000).toISOString(), created_at: new Date(Date.now() - 30 * 86400000).toISOString() },
  { id: 3, name: 'API Backend', target: 'api.liceo.edu.cl', asset_type: 'domain', last_score: null, last_score_letter: null, last_audit_at: null, created_at: new Date(Date.now() - 10 * 86400000).toISOString() },
];

const DEMO_FINDINGS: Finding[] = [
  // Audit 1 (Portal Web)
  {
    id: 101, audit_id: 1, finding_id: 'AS-2026-101', title: 'Inyección SQL (SQLi) detectada en Formulario de Búsqueda',
    description: 'Se detectó que el parámetro `query` en el endpoint `/api/search` no está correctamente saneado antes de enviarlo a la base de datos SQL. Esto permite ejecutar comandos SQL arbitrarios.',
    severity: 'critical', module: 'web', cvss_score: 9.8, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cve_id: 'CVE-2023-38646',
    evidence: 'POST /api/search HTTP/1.1\nHost: www.mipagina.cl\nContent-Type: application/json\n\n{"query": "1\' OR \'1\'=\'1"}\n\nResponse:\nHTTP/1.1 200 OK\n{\n  "status": "success",\n  "results": [ ... todo el volcado de la tabla \'users\' ... ]\n}',
    impact: 'Acceso total de lectura y escritura a la base de datos del portal web. Posibilidad de exfiltración de credenciales y datos de usuarios.',
    recommendation: 'Utilizar sentencias preparadas (Prepared Statements) o consultas parametrizadas con un ORM. Nunca concatenar strings de entrada del usuario en consultas SQL.',
    references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38646'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },
  {
    id: 102, audit_id: 1, finding_id: 'AS-2026-102', title: 'Directory Listing Habilitado en /uploads',
    description: 'El listado de directorios está habilitado para la carpeta `/uploads`. Cualquier usuario puede navegar y listar los archivos subidos al servidor.',
    severity: 'high', module: 'web', cvss_score: 7.5, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', cve_id: null,
    evidence: 'GET /uploads/ HTTP/1.1\nHost: www.mipagina.cl\n\nHTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>\n<head><title>Index of /uploads</title></head>\n<body>\n<h1>Index of /uploads</h1>\n<ul>\n<li><a href="users_export_2026.csv">users_export_2026.csv</a></li>\n<li><a href="photo.jpg">photo.jpg</a></li>\n</ul>\n</body>\n</html>',
    impact: 'Exposición de archivos privados subidos por usuarios, posibles backups de código u otra información confidencial cargada en el servidor.',
    recommendation: 'Desactivar el listado de directorios en el servidor web. En Nginx, asegúrese de tener `autoindex off;`. En Apache, elimine `Indexes` en la opción `Options`.',
    references: ['https://cwe.mitre.org/data/definitions/548.html'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },
  {
    id: 103, audit_id: 1, finding_id: 'AS-2026-103', title: 'Certificado SSL/TLS Próximo a Expirar',
    description: 'El certificado SSL/TLS configurado para el servidor expira en los próximos 7 días (fecha de expiración: 2026-06-20).',
    severity: 'medium', module: 'ssl', cvss_score: 5.4, cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N', cve_id: null,
    evidence: 'Subject: CN=www.mipagina.cl\nIssuer: Let\'s Encrypt Authority X3\nValidity:\n    Not Before: Mar 15 12:00:00 2026 GMT\n    Not After : Jun 20 12:00:00 2026 GMT (Expira pronto)',
    impact: 'Cuando el certificado expire, los navegadores mostrarán una advertencia de seguridad crítica a todos los visitantes, bloqueando el tráfico legítimo.',
    recommendation: 'Renovar el certificado SSL/TLS inmediatamente a través de su proveedor o configurar la renovación automática con Certbot/Let\'s Encrypt.',
    references: ['https://letsencrypt.org/docs/'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },
  {
    id: 104, audit_id: 1, finding_id: 'AS-2026-104', title: 'Ausencia de Cabecera Strict-Transport-Security (HSTS)',
    description: 'La cabecera HTTP Strict-Transport-Security (HSTS) no se encuentra configurada en las respuestas del servidor. HSTS fuerza al navegador a usar HTTPS en lugar de HTTP.',
    severity: 'low', module: 'web', cvss_score: 3.1, cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', cve_id: null,
    evidence: 'GET / HTTP/1.1\nHost: www.mipagina.cl\n\nHTTP/1.1 200 OK\nServer: nginx/1.24.0\nContent-Type: text/html\n(Cabecera Strict-Transport-Security ausente)',
    impact: 'Vulnerabilidad ante ataques de degradación de SSL (SSL Striping) e interceptación de tráfico (Man-in-the-Middle).',
    recommendation: 'Agregar la cabecera en la configuración de Nginx o Apache: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`',
    references: ['https://owasp.org/www-project-secure-headers/'],
    status: 'remediated', is_remediated: true, is_false_positive: false, created_at: new Date().toISOString()
  },
  
  // Audit 2 (Servidor Linux)
  {
    id: 201, audit_id: 2, finding_id: 'AS-2026-201', title: 'Puerto de Base de Datos PostgreSQL Expuesto Públicamente',
    description: 'El puerto 5432 (PostgreSQL) está abierto y accesible desde cualquier dirección IP de Internet.',
    severity: 'critical', module: 'port_scan', cvss_score: 9.8, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cve_id: null,
    evidence: 'PORT     STATE SERVICE           VERSION\n5432/tcp open  postgresql        PostgreSQL DB 15.4',
    impact: 'Ataques de fuerza bruta contra las credenciales del motor de base de datos. Posible compromiso total de los datos si se usan contraseñas débiles.',
    recommendation: 'Restringir el acceso al puerto 5432 mediante un firewall (iptables/ufw), permitiendo conexiones únicamente de las IPs del servidor backend o configurar PostgreSQL para escuchar solo en `localhost` (127.0.0.1).',
    references: ['https://www.postgresql.org/docs/current/auth-pg-hba-conf.html'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },
  {
    id: 202, audit_id: 2, finding_id: 'AS-2026-202', title: 'Servidor SSH Habilitado con Autenticación por Contraseña',
    description: 'El servicio SSH en el puerto 22 acepta autenticación mediante contraseña (password authentication) en lugar de requerir obligatoriamente claves públicas SSH.',
    severity: 'high', module: 'port_scan', cvss_score: 7.5, cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', cve_id: null,
    evidence: 'SSH Server Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3\nSupported authentications: publickey,password',
    impact: 'Riesgo elevado de compromiso del servidor ante ataques automatizados de fuerza bruta y diccionario.',
    recommendation: 'Desactivar la autenticación por contraseña en `/etc/ssh/sshd_config` configurando `PasswordAuthentication no` y exigir el uso de claves SSH.',
    references: ['https://www.ssh.com/academy/ssh/sshd_config'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },

  // Audit 3 (Scan DNS)
  {
    id: 301, audit_id: 3, finding_id: 'AS-2026-301', title: 'DNSSEC No Habilitado',
    description: 'El dominio no tiene configurado DNSSEC (Domain Name System Security Extensions), lo que deja las respuestas DNS vulnerables a falsificaciones.',
    severity: 'medium', module: 'dns', cvss_score: 5.0, cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N', cve_id: null,
    evidence: 'Querying DNSSEC records for liceo.edu.cl...\nNo DS or DNSKEY records found in authority section.',
    impact: 'Vulnerabilidad ante ataques de envenenamiento de caché DNS (DNS spoofing/poisoning), donde un atacante puede redirigir el tráfico legítimo a servidores falsos.',
    recommendation: 'Habilitar DNSSEC con su registrador de dominios (NIC Chile) y configurar las firmas criptográficas en su proveedor DNS.',
    references: ['https://www.cloudflare.com/dns/dnssec/what-is-dnssec/'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  },
  {
    id: 302, audit_id: 3, finding_id: 'AS-2026-302', title: 'Registro DMARC Faltante',
    description: 'No se encontró una política DMARC (Domain-based Message Authentication, Reporting, and Conformance) configurada para el dominio.',
    severity: 'medium', module: 'dns', cvss_score: 5.0, cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N', cve_id: null,
    evidence: 'DMARC record lookup for liceo.edu.cl...\nStatus: NXDOMAIN (No DMARC record found)',
    impact: 'Facilita la suplantación de identidad por correo electrónico (email spoofing) utilizando la identidad del dominio institucional para campañas de phishing.',
    recommendation: 'Crear un registro TXT para `_dmarc.liceo.edu.cl` con una política inicial de monitoreo, por ejemplo: `v=DMARC1; p=none; rua=mailto:dmarc-reports@liceo.edu.cl` y luego avanzar hacia políticas más restrictivas (`quarantine` o `reject`).',
    references: ['https://dmarc.org/'],
    status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
  }
];

export const seedMockData = () => {
  if (typeof window === 'undefined') return;
  
  if (!localStorage.getItem('mock_audits')) {
    localStorage.setItem('mock_audits', JSON.stringify(DEMO_AUDITS));
  }
  
  if (!localStorage.getItem('mock_assets')) {
    localStorage.setItem('mock_assets', JSON.stringify(DEMO_ASSETS));
  }
  
  if (!localStorage.getItem('mock_reports')) {
    const demoReports: Report[] = [
      { id: 1, audit_id: 1, audit_title: 'Auditoría Portal Web', report_type: 'full', file_size: 154020, created_at: new Date(Date.now() - 2 * 86400000).toISOString(), status: 'ready' },
      { id: 2, audit_id: 2, audit_title: 'Revisión Servidor Linux', report_type: 'technical', file_size: 98510, created_at: new Date(Date.now() - 5 * 86400000).toISOString(), status: 'ready' },
    ];
    localStorage.setItem('mock_reports', JSON.stringify(demoReports));
  }
  
  if (!localStorage.getItem('mock_findings')) {
    localStorage.setItem('mock_findings', JSON.stringify(DEMO_FINDINGS));
  }
};

export const getMockAudits = (): Audit[] => {
  seedMockData();
  const raw = localStorage.getItem('mock_audits');
  return raw ? JSON.parse(raw) : [];
};

export const getMockAudit = (id: number): Audit | null => {
  const audits = getMockAudits();
  const found = audits.find(a => a.id === id);
  if (!found) return null;
  // Load findings for this audit to populate fields if needed
  const findings = getMockFindings(id);
  found.findings_count = findings.length;
  found.critical_count = findings.filter(f => f.severity === 'critical').length;
  found.high_count = findings.filter(f => f.severity === 'high').length;
  found.medium_count = findings.filter(f => f.severity === 'medium').length;
  found.low_count = findings.filter(f => f.severity === 'low').length;
  found.info_count = findings.filter(f => f.severity === 'info').length;
  return found;
};

export const createMockAudit = (data: any): Audit => {
  const audits = getMockAudits();
  const newId = audits.length > 0 ? Math.max(...audits.map(a => a.id)) + 1 : 1;
  const newAudit: Audit = {
    id: newId,
    title: data.title || `Auditoría ${data.target}`,
    target: data.target,
    target_type: data.target_type || 'domain',
    status: 'running',
    profile: data.profile || 'full',
    score: null,
    security_score: null,
    score_letter: null,
    created_at: new Date().toISOString(),
    completed_at: null,
    duration: null,
    findings_count: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    info_count: 0,
    progress: 0,
    current_module: 'Inicializando...',
    notes: data.notes || '',
    options: data.scan_options || {},
    modules: data.modules || { osint: true, ssl: true, web: true, ports: true }
  };
  
  audits.unshift(newAudit); // add to top
  localStorage.setItem('mock_audits', JSON.stringify(audits));
  return newAudit;
};

export const updateMockAudit = (audit: Audit): void => {
  const audits = getMockAudits();
  const updated = audits.map(a => a.id === audit.id ? audit : a);
  localStorage.setItem('mock_audits', JSON.stringify(updated));
};

export const deleteMockAudit = (id: number): void => {
  const audits = getMockAudits();
  const filtered = audits.filter(a => a.id !== id);
  localStorage.setItem('mock_audits', JSON.stringify(filtered));
};

export const getMockFindings = (auditId: number): Finding[] => {
  seedMockData();
  const raw = localStorage.getItem('mock_findings');
  if (!raw) return [];
  const all: Finding[] = JSON.parse(raw);
  return all.filter(f => f.audit_id === auditId);
};

export const updateMockFinding = (auditId: number, findingId: number, data: Partial<Finding>): Finding | null => {
  seedMockData();
  const raw = localStorage.getItem('mock_findings');
  if (!raw) return null;
  const all: Finding[] = JSON.parse(raw);
  let updatedFinding: Finding | null = null;
  
  const updated = all.map(f => {
    if (f.id === findingId && f.audit_id === auditId) {
      updatedFinding = {
        ...f,
        ...data,
        // sync bindings
        is_remediated: data.status === 'remediated' || data.is_remediated,
        is_false_positive: data.status === 'false_positive' || data.is_false_positive
      };
      return updatedFinding;
    }
    return f;
  });
  
  localStorage.setItem('mock_findings', JSON.stringify(updated));
  return updatedFinding;
};

export const getMockAssets = (): Asset[] => {
  seedMockData();
  const raw = localStorage.getItem('mock_assets');
  return raw ? JSON.parse(raw) : [];
};

export const createMockAsset = (data: any): Asset => {
  const assets = getMockAssets();
  const newId = assets.length > 0 ? Math.max(...assets.map(a => a.id)) + 1 : 1;
  const newAsset: Asset = {
    id: newId,
    name: data.name,
    target: data.target,
    asset_type: data.asset_type || 'domain',
    last_score: null,
    last_score_letter: null,
    last_audit_at: null,
    created_at: new Date().toISOString()
  };
  assets.push(newAsset);
  localStorage.setItem('mock_assets', JSON.stringify(assets));
  return newAsset;
};

export const deleteMockAsset = (id: number): void => {
  const assets = getMockAssets();
  const filtered = assets.filter(a => a.id !== id);
  localStorage.setItem('mock_assets', JSON.stringify(filtered));
};

export const getMockReports = (): Report[] => {
  seedMockData();
  const raw = localStorage.getItem('mock_reports');
  return raw ? JSON.parse(raw) : [];
};

export const createMockReport = (auditId: number, reportType: string): Report => {
  const reports = getMockReports();
  const audits = getMockAudits();
  const audit = audits.find(a => a.id === auditId);
  const auditTitle = audit ? audit.title : `Auditoría #${auditId}`;
  
  const newId = reports.length > 0 ? Math.max(...reports.map(r => r.id)) + 1 : 1;
  const newReport: Report = {
    id: newId,
    audit_id: auditId,
    audit_title: auditTitle,
    report_type: reportType || 'full',
    file_size: Math.floor(Math.random() * 80000) + 50000, // 50kb to 130kb
    created_at: new Date().toISOString(),
    status: 'ready'
  };
  
  reports.unshift(newReport);
  localStorage.setItem('mock_reports', JSON.stringify(reports));
  return newReport;
};

export const deleteMockReport = (id: number): void => {
  const reports = getMockReports();
  const filtered = reports.filter(r => r.id !== id);
  localStorage.setItem('mock_reports', JSON.stringify(filtered));
};

export const generateMockFindingsForAudit = (auditId: number, target: string) => {
  if (typeof window === 'undefined') return;
  seedMockData();
  const raw = localStorage.getItem('mock_findings') || '[]';
  const findings: Finding[] = JSON.parse(raw);
  
  // check if findings already exist to prevent duplicate generation
  if (findings.some(f => f.audit_id === auditId)) return;

  const newFindings: Finding[] = [
    {
      id: auditId * 1000 + 1, audit_id: auditId, finding_id: `AS-DYN-${auditId}-001`,
      title: 'Ausencia de Cabecera Content-Security-Policy (CSP)',
      description: 'El servidor web responde sin la cabecera HTTP Content-Security-Policy (CSP). Esta cabecera ayuda a prevenir vulnerabilidades como Cross-Site Scripting (XSS) y Clickjacking.',
      severity: 'high', module: 'web', cvss_score: 7.2, cve_id: null,
      evidence: `GET / HTTP/1.1\nHost: ${target}\n\nHTTP/1.1 200 OK\n(Content-Security-Policy missing)`,
      impact: 'Riesgo de ejecución de scripts JavaScript maliciosos inyectados por atacantes en el contexto de sesión de los usuarios.',
      recommendation: 'Implementar una política de CSP restrictiva en la configuración del servidor web o en las respuestas HTTP de la aplicación.',
      references: ['https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Content-Security-Policy'],
      status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
    },
    {
      id: auditId * 1000 + 2, audit_id: auditId, finding_id: `AS-DYN-${auditId}-002`,
      title: 'Puerto de Administración expuesto públicamente (Puerto 22 - SSH)',
      description: 'El puerto 22 (SSH) está expuesto a la red pública. El banner de versión revela que el servidor usa un software potencialmente desactualizado.',
      severity: 'medium', module: 'port_scan', cvss_score: 5.3, cve_id: null,
      evidence: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3`,
      impact: 'Ataques constantes de fuerza bruta contra las credenciales del servidor.',
      recommendation: 'Limitar el acceso al puerto 22 utilizando una VPN, un firewall para permitir IPs exclusivas, o cambiar el puerto SSH por uno no estándar.',
      references: ['https://cwe.mitre.org/data/definitions/287.html'],
      status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
    },
    {
      id: auditId * 1000 + 3, audit_id: auditId, finding_id: `AS-DYN-${auditId}-003`,
      title: 'Cabeceras X-Frame-Options no configuradas (Clickjacking)',
      description: 'La cabecera X-Frame-Options no se incluye en las respuestas de la página web, lo que permite que el sitio sea enmarcado en un iframe de otro dominio.',
      severity: 'low', module: 'web', cvss_score: 3.4, cve_id: null,
      evidence: `HTTP/1.1 200 OK\n(X-Frame-Options header missing)`,
      impact: 'Posibilidad de ataques de Clickjacking donde un usuario es engañado para realizar acciones no intencionadas.',
      recommendation: 'Agregar la cabecera HTTP: `X-Frame-Options: SAMEORIGIN` o usar la directiva `frame-ancestors` en CSP.',
      references: ['https://owasp.org/www-community/attacks/Clickjacking'],
      status: 'open', is_remediated: false, is_false_positive: false, created_at: new Date().toISOString()
    }
  ];
  
  localStorage.setItem('mock_findings', JSON.stringify([...findings, ...newFindings]));
};
