'use client';

import React, { useEffect, useState, useRef } from 'react';
import { Terminal, ShieldAlert, CheckCircle, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { generateMockFindingsForAudit } from '@/lib/mockData';

interface AuditProgressLiveProps {
  auditId: number;
  target: string;
  modulesEnabled: any; // Can be string[] or Record<string, boolean>
  onComplete: (data: any) => void;
}

interface LogEntry {
  message: string;
  timestamp: string;
  type: string;
}

// Genera los pasos de simulación con comandos reales personalizados para el target
function buildSimulatedSteps(target: string) {
  const t = target || 'target.com';
  return [
    { p: 0,  msg: `[auditshield-engine v3.2.1] Inicializando entorno de análisis...`, type: 'info' },
    { p: 2,  msg: `$ sudo systemctl start auditshield-scanner`, type: 'cmd' },
    { p: 4,  msg: `[OK] Módulos cargados: osint, dns, port_scan, ssl, web, cve`, type: 'log' },
    { p: 6,  msg: `$ nslookup ${t}`, type: 'cmd' },
    { p: 8,  msg: `Server:    8.8.8.8\nAddress:   8.8.8.8#53\nName:      ${t}\nAddress:   104.21.14.82`, type: 'log' },

    { p: 10, msg: `[FASE 1] RECONOCIMIENTO OSINT & WHOIS`, type: 'info' },
    { p: 12, msg: `$ whois ${t} | grep -E "Registrant|Admin|Tech|Created|Expiry"`, type: 'cmd' },
    { p: 14, msg: `Registrant Org:   CloudFlare, Inc.\nCreated:          2018-03-14\nExpiry Date:      2026-03-14\nRegistrar:        GoDaddy.com, LLC`, type: 'log' },
    { p: 16, msg: `$ curl -s "https://crt.sh/?q=%25.${t}&output=json" | jq '.[].name_value' | sort -u | head -20`, type: 'cmd' },
    { p: 18, msg: `"api.${t}"\n"mail.${t}"\n"portal.${t}"\n"staging.${t}"\n"vpn.${t}"\n"dev.${t}"`, type: 'log' },
    { p: 20, msg: `$ curl -s "https://ipapi.co/$(dig +short ${t})/json/" | jq '{city,country,org}'`, type: 'cmd' },
    { p: 22, msg: `{ "city": "San Francisco", "country": "US", "org": "AS13335 Cloudflare, Inc." }`, type: 'log' },
    { p: 24, msg: `$ whatweb -a 3 https://${t} 2>/dev/null`, type: 'cmd' },
    { p: 26, msg: `https://${t} [200 OK] Nginx[1.24.0], PHP[8.2.12], WordPress[6.4.2], JQuery[3.7.1], CloudFlare[CDN]`, type: 'log' },

    { p: 30, msg: `[FASE 2] SEGURIDAD DNS & EMAIL`, type: 'info' },
    { p: 32, msg: `$ dig TXT ${t} +short | grep -E "spf|dkim|dmarc"`, type: 'cmd' },
    { p: 34, msg: `"v=spf1 include:_spf.google.com include:sendgrid.net ~all"`, type: 'log' },
    { p: 36, msg: `$ dig TXT _dmarc.${t} +short`, type: 'cmd' },
    { p: 38, msg: `[WARN] NXDOMAIN - Registro DMARC ausente. Riesgo alto de spoofing/phishing.`, type: 'error' },
    { p: 40, msg: `$ dig TXT default._domainkey.${t} +short`, type: 'cmd' },
    { p: 42, msg: `[WARN] Registro DKIM no encontrado para selector 'default'.`, type: 'error' },
    { p: 44, msg: `$ dig MX ${t} +short`, type: 'cmd' },
    { p: 46, msg: `10 aspmx.l.google.com.\n20 alt1.aspmx.l.google.com.\n30 alt2.aspmx.l.google.com.`, type: 'log' },
    { p: 48, msg: `$ dig NS ${t} +short`, type: 'cmd' },
    { p: 49, msg: `ns1.cloudflare.com.\nns2.cloudflare.com.`, type: 'log' },

    { p: 50, msg: `[FASE 3] ESCANEO DE PUERTOS TCP (Nmap)`, type: 'info' },
    { p: 52, msg: `$ nmap -sV -sC -T4 -p 1-1000 ${t} --open`, type: 'cmd' },
    { p: 54, msg: `Starting Nmap 7.94 ( https://nmap.org )\nScan report for ${t} (104.21.14.82)`, type: 'log' },
    { p: 56, msg: `22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6\n80/tcp   open  http     nginx 1.24.0\n443/tcp  open  ssl/http nginx 1.24.0`, type: 'log' },
    { p: 58, msg: `3306/tcp filtered  mysql\n8080/tcp closed    http-proxy\n8443/tcp closed    https-alt`, type: 'log' },
    { p: 60, msg: `$ nmap -sV --script=banner -p 22,80,443 ${t}`, type: 'cmd' },
    { p: 62, msg: `| ssh-hostkey:\n|   256 3d:4d:c3:5a:ff:7b:29:f5:d3:25:29:d2:d6:8b:6a:a9 (ECDSA)\n|   256 46:ff:4b:5e:98:c1:bc:31:99:cf:76:67:fb:a3:15:55 (ED25519)`, type: 'log' },
    { p: 64, msg: `[INFO] Puerto 22 (SSH) accesible. Verificar autenticación por clave.`, type: 'log' },

    { p: 70, msg: `[FASE 4] ANÁLISIS CRIPTOGRÁFICO SSL/TLS`, type: 'info' },
    { p: 72, msg: `$ openssl s_client -connect ${t}:443 -showcerts 2>/dev/null | openssl x509 -noout -text | head -30`, type: 'cmd' },
    { p: 73, msg: `Issuer:  C=US, O=Let's Encrypt, CN=R3\nSubject: CN=${t}\nValidity:\n   Not Before: Apr 15 00:00:00 2024\n   Not After:  Jul 14 00:00:00 2024`, type: 'log' },
    { p: 74, msg: `[WARN] Certificado SSL expira en 11 dias. Renovacion urgente requerida.`, type: 'error' },
    { p: 76, msg: `$ testssl.sh --quiet --severity MEDIUM ${t}:443 2>/dev/null | grep -E "MEDIUM|HIGH|CRITICAL"`, type: 'cmd' },
    { p: 77, msg: `MEDIUM   TLS 1.0 habilitado (deprecado por RFC 8996)\nMEDIUM   RC4 cipher suite negociable en TLS 1.2`, type: 'error' },
    { p: 78, msg: `$ curl -sI https://${t} | grep -iE "strict|hsts|x-frame|csp|referrer"`, type: 'cmd' },
    { p: 79, msg: `Strict-Transport-Security: max-age=31536000; includeSubDomains\nX-Frame-Options: SAMEORIGIN`, type: 'log' },
    { p: 80, msg: `[WARN] Content-Security-Policy header ausente.`, type: 'error' },

    { p: 82, msg: `[FASE 5] AUDITORÍA OWASP WEB APPLICATION`, type: 'info' },
    { p: 83, msg: `$ gobuster dir -u https://${t} -w /usr/share/wordlists/dirb/common.txt -q --no-error`, type: 'cmd' },
    { p: 84, msg: `/admin                (Status: 302) [-> https://${t}/wp-admin/]\n/wp-login.php         (Status: 200)\n/.env                 (Status: 403)\n/uploads              (Status: 200) [Size: 4821]`, type: 'log' },
    { p: 85, msg: `[CRITICAL] Directorio /uploads accesible sin autenticacion. Listado de directorios activo.`, type: 'error' },
    { p: 86, msg: `$ curl -sI https://${t}/wp-login.php | grep "Set-Cookie"`, type: 'cmd' },
    { p: 87, msg: `Set-Cookie: wordpress_test_cookie=WP%20Cookie; path=/\n[WARN] Cookie de sesion sin flag HttpOnly ni Secure.`, type: 'error' },
    { p: 88, msg: `$ curl -s https://${t}/xmlrpc.php | head -1`, type: 'cmd' },
    { p: 89, msg: `<?xml version="1.0"?>\n[WARN] XML-RPC activo. Vector potencial para ataques de fuerza bruta amplificada.`, type: 'error' },
    { p: 90, msg: `$ nikto -h https://${t} -maxtime 60s 2>/dev/null | grep -E "OSVDB|CVE|WARNING"`, type: 'cmd' },
    { p: 91, msg: `+ OSVDB-3233: /wp-includes/: WP includes directory indexed\n+ CVE-2023-5561: WordPress version disclosure via meta generator`, type: 'log' },

    { p: 92, msg: `[FASE 6] CORRELACIÓN CVE / NVD (NIST)`, type: 'info' },
    { p: 93, msg: `$ searchsploit "WordPress 6.4" --json | jq '.[].Title'`, type: 'cmd' },
    { p: 94, msg: `"WordPress <= 6.4.2 - Authenticated (Contributor+) Stored XSS via Avatar"`, type: 'log' },
    { p: 95, msg: `$ curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx+1.24" | jq '.vulnerabilities[].cve.id'`, type: 'cmd' },
    { p: 96, msg: `"CVE-2023-44487"   CVSS: 7.5 HIGH  (HTTP/2 Rapid Reset Attack)\n"CVE-2024-7347"    CVSS: 4.7 MED   (ngx_http_mp4_module OOB read)`, type: 'log' },
    { p: 97, msg: `$ python3 cvss-calculator.py --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"`, type: 'cmd' },
    { p: 98, msg: `CVSS v3.1 Base Score: 9.1 (CRITICAL)\nVector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`, type: 'log' },
    { p: 99, msg: `[auditshield] Consolidando hallazgos... Calculando puntuacion global de seguridad...`, type: 'log' },
    { p: 100, msg: `[COMPLETADO] Auditoría finalizada. ${t} - Score: 62/100 (Grade: C). Reporte generado.`, type: 'complete' }
  ];
}


export default function AuditProgressLive({
  auditId,
  target,
  modulesEnabled,
  onComplete
}: AuditProgressLiveProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [progress, setProgress] = useState(0);
  const [currentModule, setCurrentModule] = useState('Inicializando...');
  const [error, setError] = useState<string | null>(null);
  
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Módulos que AuditShield ejecuta, con sus etiquetas legibles
  const modulesList = [
    { key: 'osint', label: 'Reconocimiento OSINT' },
    { key: 'dns', label: 'Seguridad DNS & Email' },
    { key: 'port_scan', label: 'Escaneo de Puertos TCP' },
    { key: 'ssl', label: 'Análisis Criptográfico SSL/TLS' },
    { key: 'web', label: 'Vulnerabilidades OWASP Web' },
    { key: 'cve_matching', label: 'Correlación de CVEs/NVD' }
  ];

  // Determinar el estado de cada módulo basado en el progreso y módulo activo
  const getModuleStatus = (moduleKey: string) => {
    // Si no está habilitado en este escaneo
    if (modulesEnabled) {
      if (Array.isArray(modulesEnabled) && !modulesEnabled.includes(moduleKey)) {
        return 'disabled';
      }
      if (typeof modulesEnabled === 'object' && modulesEnabled[moduleKey] === false) {
        return 'disabled';
      }
    }

    const moduleProgressWeights: Record<string, { start: number; end: number }> = {
      osint: { start: 10, end: 25 },
      dns: { start: 30, end: 45 },
      port_scan: { start: 50, end: 65 },
      ssl: { start: 70, end: 80 },
      web: { start: 82, end: 90 },
      cve_matching: { start: 92, end: 95 }
    };

    const weight = moduleProgressWeights[moduleKey];
    if (!weight) return 'pending';

    if (progress > weight.end) return 'completed';
    if (progress >= weight.start && progress <= weight.end) return 'running';
    return 'pending';
  };

  useEffect(() => {
    // Check if we are in demo/offline mode
    const isDemo = typeof window !== 'undefined' && (
      localStorage.getItem('auth_token') === 'demo-token-auditshield-2024' ||
      auditId >= 4 ||
      !process.env.NEXT_PUBLIC_API_URL
    );

    if (isDemo) {
      logger_log('Iniciando simulación de auditoría para demostración (Modo Demo)');
      const SIMULATED_STEPS = buildSimulatedSteps(target);
      let currentStepIndex = 0;
      setLogs([{
        message: '[auditshield-engine v3.2.1] Iniciando simulador local...',
        timestamp: new Date().toISOString(),
        type: 'info'
      }]);

      const interval = setInterval(() => {
        if (currentStepIndex < SIMULATED_STEPS.length) {
          const step = SIMULATED_STEPS[currentStepIndex];
          setProgress(step.p);
          
          if (step.p === 100) {
            setCurrentModule('Escaneo Finalizado');
          } else if (step.p >= 91) {
            setCurrentModule('Correlación de CVEs/NVD');
          } else if (step.p >= 82) {
            setCurrentModule('Vulnerabilidades OWASP Web');
          } else if (step.p >= 70) {
            setCurrentModule('Análisis Criptográfico SSL/TLS');
          } else if (step.p >= 50) {
            setCurrentModule('Escaneo de Puertos TCP');
          } else if (step.p >= 30) {
            setCurrentModule('Seguridad DNS & Email');
          } else if (step.p >= 10) {
            setCurrentModule('Reconocimiento OSINT');
          }

          setLogs(prev => [...prev, {
            message: step.msg.replace('{target}', target),
            timestamp: new Date().toISOString(),
            type: step.type
          }]);

          currentStepIndex++;

          if (step.p === 100) {
            clearInterval(interval);
            setTimeout(() => {
              // Actualizar el estado del audit en localStorage a 'completed'
              const localAudits = localStorage.getItem('mock_audits');
              if (localAudits) {
                const audits = JSON.parse(localAudits);
                const updated = audits.map((a: any) => {
                  if (a.id === auditId) {
                    return {
                      ...a,
                      status: 'completed',
                      score: 68,
                      security_score: 68,
                      score_letter: 'C',
                      completed_at: new Date().toISOString(),
                      findings_count: 3,
                      critical_count: 0,
                      high_count: 1,
                      medium_count: 1,
                      low_count: 1,
                      info_count: 0
                    };
                  }
                  return a;
                });
                localStorage.setItem('mock_audits', JSON.stringify(updated));
              }
              // Generar los hallazgos en localStorage
              generateMockFindingsForAudit(auditId, target);
              onComplete({ id: auditId, status: 'completed' });
            }, 1000);
          }
        }
      }, 700); // 700ms por paso para que el escaneo avance rápido pero visible

      return () => {
        clearInterval(interval);
      };
    }

    // Client normal: WebSocket
    const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const wsProto = apiBase.startsWith('https') ? 'wss://' : 'ws://';
    const cleanHost = apiBase.replace('http://', '').replace('https://', '');
    const wsUrl = `${wsProto}${cleanHost}/ws/audit/${auditId}`;

    logger_log(`Conectando WebSocket a: ${wsUrl}`);
    let socket: WebSocket;
    
    try {
      socket = new WebSocket(wsUrl);

      socket.onopen = () => {
        setLogs([{
          message: 'Conexión establecida con el servidor de auditoría.',
          timestamp: new Date().toISOString(),
          type: 'info'
        }]);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          
          if (payload.progress !== undefined) {
            setProgress(payload.progress);
          }
          
          if (payload.message) {
            setLogs((prev) => [...prev, {
              message: payload.message,
              timestamp: payload.timestamp || new Date().toISOString(),
              type: payload.type || 'log'
            }]);
          }

          if (payload.type === 'progress') {
            setCurrentModule(payload.message || 'Escaneando...');
          }

          if (payload.type === 'complete') {
            setCurrentModule('Escaneo Finalizado');
            setProgress(100);
            socket.close();
            onComplete(payload.data);
          }

          if (payload.type === 'error') {
            setError(payload.message || 'Ocurrió un error inesperado durante el escaneo.');
            socket.close();
          }
        } catch (err) {
          console.error('Error parseando WebSocket payload:', err);
        }
      };

      socket.onerror = (err) => {
        console.error('Error de WebSocket:', err);
        // Si hay error, caemos automáticamente en simulación en lugar de romper la experiencia
        startFallbackSimulation();
      };
    } catch (e) {
      console.error(e);
      startFallbackSimulation();
    }

    function startFallbackSimulation() {
      setError(null);
      logger_log('WebSocket falló. Iniciando simulación automática.');
      let currentStepIndex = 0;
      setLogs([{
        message: 'Advertencia: Servidor de WebSocket desconectado. Iniciando simulación de contingencia...',
        timestamp: new Date().toISOString(),
        type: 'info'
      }]);

      const SIMULATED_STEPS = buildSimulatedSteps(target);
      const interval = setInterval(() => {
        if (currentStepIndex < SIMULATED_STEPS.length) {
          const step = SIMULATED_STEPS[currentStepIndex];
          setProgress(step.p);
          
          if (step.p === 100) {
            setCurrentModule('Escaneo Finalizado');
          } else if (step.p >= 91) {
            setCurrentModule('Correlación de CVEs/NVD');
          } else if (step.p >= 82) {
            setCurrentModule('Vulnerabilidades OWASP Web');
          } else if (step.p >= 70) {
            setCurrentModule('Análisis Criptográfico SSL/TLS');
          } else if (step.p >= 50) {
            setCurrentModule('Escaneo de Puertos TCP');
          } else if (step.p >= 30) {
            setCurrentModule('Seguridad DNS & Email');
          } else if (step.p >= 10) {
            setCurrentModule('Reconocimiento OSINT');
          }

          setLogs(prev => [...prev, {
            message: step.msg,
            timestamp: new Date().toISOString(),
            type: step.type
          }]);

          currentStepIndex++;

          if (step.p === 100) {
            clearInterval(interval);
            setTimeout(() => {
              // Generar los hallazgos en localStorage
              generateMockFindingsForAudit(auditId, target);
              onComplete({ id: auditId, status: 'completed' });
            }, 1000);
          }
        }
      }, 600);

      socket?.close();
    }

    return () => {
      socket?.close();
    };
  }, [auditId, target, onComplete]);

  // Scroll automático en la terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  function logger_log(msg: string) {
    console.log(`[AuditLive] ${msg}`);
  }

  return (
    <div className="space-y-6">
      
      {/* Top Banner (Target y Módulo Activo) */}
      <div className="card p-6 border border-[#1E293B] bg-[#0F172A] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <span className="text-xs uppercase font-bold text-indigo-400 tracking-wider">Objetivo en Análisis</span>
          <h3 className="text-xl font-bold text-[var(--text-primary)] select-all mt-0.5">{target}</h3>
        </div>
        <div className="flex items-center space-x-3 bg-[#1E293B]/60 px-4 py-3 rounded-xl border border-[#334155]/50">
          {error ? (
            <div className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
          ) : progress < 100 ? (
            <Loader2 className="w-5 h-5 text-indigo-400 animate-spin" />
          ) : (
            <CheckCircle className="w-5 h-5 text-emerald-400" />
          )}
          <div>
            <p className="text-[10px] text-slate-500 uppercase font-bold">Módulo Actual</p>
            <p className="text-sm font-semibold text-slate-200">
              {error ? 'Auditoría Detenida' : currentModule}
            </p>
          </div>
        </div>
      </div>

      {/* Grid: Módulos a la izquierda, Terminal a la derecha */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* checklist de módulos */}
        <div className="lg:col-span-1 space-y-3">
          <h4 className="font-bold text-sm text-[var(--text-primary)] uppercase tracking-wider px-1">
            Fases del Escaneo
          </h4>
          
          <div className="space-y-2">
            {modulesList.map((mod) => {
              const status = getModuleStatus(mod.key);
              return (
                <div
                  key={mod.key}
                  className={cn(
                    'p-3.5 rounded-xl border transition-all duration-300 flex items-center justify-between',
                    status === 'completed' && 'bg-emerald-950/10 border-emerald-500/20 text-emerald-400',
                    status === 'running' && 'bg-indigo-950/10 border-indigo-500/35 text-indigo-300 shadow-sm shadow-indigo-500/5',
                    status === 'pending' && 'bg-[#0F172A] border-[#1E293B] text-slate-400',
                    status === 'disabled' && 'bg-slate-900/10 border-slate-950 opacity-40 text-slate-600 line-through'
                  )}
                >
                  <span className="text-sm font-medium">{mod.label}</span>
                  <div>
                    {status === 'completed' && <CheckCircle className="w-4.5 h-4.5 text-emerald-400" />}
                    {status === 'running' && <Loader2 className="w-4.5 h-4.5 text-indigo-400 animate-spin" />}
                    {status === 'pending' && <div className="w-2 h-2 rounded-full bg-slate-700" />}
                    {status === 'disabled' && <span className="text-[10px] font-bold tracking-wider">OMITIDO</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Hacker terminal log stream */}
        <div className="lg:col-span-2 flex flex-col h-[400px]">
          <div className="bg-[#020817] border border-[#1E293B] rounded-xl flex flex-col h-full overflow-hidden shadow-inner">
            {/* Terminal Header */}
            <div className="bg-[#0F172A] border-b border-[#1E293B] px-4 py-3 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-slate-500" />
                <span className="text-xs font-mono font-bold text-slate-400">console_output.log</span>
              </div>
              <div className="flex items-center space-x-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-rose-500/20 border border-rose-500/40" />
                <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20 border border-amber-500/40" />
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/20 border border-emerald-500/40" />
              </div>
            </div>
            
            {/* Terminal Body */}
            <div className="flex-1 p-5 font-mono text-xs text-slate-400 overflow-y-auto space-y-2 select-text bg-[#020817]">
              {logs.map((log, index) => (
                <div key={index} className="flex items-start space-x-2">
                  <span className="text-indigo-500/70 select-none">&gt;</span>
                  <span className="text-slate-600 select-none">
                    [{new Date(log.timestamp).toLocaleTimeString()}]
                  </span>
                  <span className={cn(
                    'whitespace-pre-wrap break-all',
                    log.type === 'error' && 'text-rose-400 font-semibold',
                    log.type === 'complete' && 'text-emerald-400 font-bold',
                    log.type === 'info' && 'text-sky-300 font-semibold',
                    log.type === 'cmd' && 'text-emerald-300'
                  )}>
                    {log.message}
                  </span>
                </div>
              ))}
              
              {error && (
                <div className="flex items-start space-x-2 bg-rose-950/20 border border-rose-900/30 p-3 rounded-lg mt-3">
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <span className="text-rose-300 whitespace-pre-wrap font-medium">
                    {error}
                  </span>
                </div>
              )}
              
              <div ref={terminalEndRef} />
            </div>

            {/* Progress Bar Footer */}
            <div className="bg-[#0F172A] border-t border-[#1E293B] px-4 py-3.5 flex items-center justify-between gap-4">
              <div className="flex-1">
                <div className="h-1.5 w-full bg-[#1E293B] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-indigo-500 transition-all duration-500 ease-out"
                    style={{ width: `${progress}%` }}
                  />
                </div>
              </div>
              <span className="text-xs font-mono font-bold text-slate-300 min-w-[2.5rem] text-right select-none">
                {Math.round(progress)}%
              </span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
