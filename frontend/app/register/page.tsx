'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield, Mail, Lock, Eye, EyeOff, User, UserCircle,
  Loader2, AlertCircle, ArrowRight, CheckCircle2, Terminal
} from 'lucide-react';
import toast from 'react-hot-toast';
import { authApi } from '@/lib/api';

interface FormData {
  full_name: string;
  email: string;
  username: string;
  password: string;
  confirmPassword: string;
}

const TERMINAL_LINES = [
  '$ openssl version',
  'OpenSSL 3.2.1 14 Jan 2024 (Library: OpenSSL 3.2.1)',
  '$ nmap --version',
  'Nmap version 7.95 ( https://nmap.org )',
  '$ auditshield --init --mode=auditor',
  '[✓] Kernel security modules loaded',
  '[✓] Vulnerability databases synced (CVE-2024)',
  '[✓] OWASP ZAP engine initialized',
  '[✓] PDF report compiler ready',
  '$ echo "Sistema listo para auditorías"',
  'Sistema listo para auditorías',
  '$ _',
];

export default function RegisterPage() {
  const router = useRouter();
  const [form, setForm] = useState<FormData>({
    full_name: '',
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let active = true;
    let idx = 0;
    const interval = setInterval(() => {
      if (!active) return;
      if (idx < TERMINAL_LINES.length) {
        const line = TERMINAL_LINES[idx];
        if (line) {
          setTerminalLines(prev => [...prev, line]);
        }
        idx++;
      } else {
        clearInterval(interval);
      }
    }, 400);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!form.full_name || !form.email || !form.username || !form.password) {
      setError('Por favor completa todos los campos.');
      return;
    }
    if (form.password !== form.confirmPassword) {
      setError('Las contraseñas no coinciden.');
      return;
    }
    if (form.password.length < 8) {
      setError('La contraseña debe tener al menos 8 caracteres.');
      return;
    }
    setLoading(true);
    try {
      await authApi.register({
        full_name: form.full_name,
        email: form.email,
        username: form.username,
        password: form.password,
      });
      toast.success('¡Cuenta creada! Por favor inicia sesión.');
      router.push('/login');
    } catch (err: any) {
      const message = err.response?.data?.detail || 'Error al crear la cuenta.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const passwordStrength = form.password.length < 4 ? 0 : form.password.length < 6 ? 1 : form.password.length < 8 ? 2 : form.password.length < 12 ? 3 : 4;
  const strengthColors = ['#ef4444', '#f97316', '#eab308', '#10b981'];
  const strengthLabels = ['Muy débil', 'Débil', 'Aceptable', 'Fuerte'];

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: 'rgba(2, 8, 23, 0.8)',
    border: '1px solid #1e293b',
    borderRadius: 12,
    padding: '12px 16px 12px 40px',
    fontSize: 14,
    color: '#e2e8f0',
    outline: 'none',
    transition: 'border-color 0.2s, box-shadow 0.2s',
    fontFamily: 'Inter, sans-serif',
    boxSizing: 'border-box',
  };

  const labelStyle: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: '0.12em',
    textTransform: 'uppercase',
    color: '#64748b',
    display: 'block',
    marginBottom: 6,
  };

  const iconStyle: React.CSSProperties = {
    position: 'absolute',
    left: 14,
    top: '50%',
    transform: 'translateY(-50%)',
    pointerEvents: 'none',
    color: '#475569',
    transition: 'color 0.2s',
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      background: '#020817',
      fontFamily: 'Inter, system-ui, sans-serif',
      overflow: 'hidden',
    }}>
      <style>{`
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-8px); } }
        .reg-input:focus { border-color: #818cf8 !important; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1) !important; }
      `}</style>

      {/* ── LEFT PANEL ── */}
      <div style={{
        display: 'none',
        width: '45%',
        position: 'relative',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: 48,
        overflow: 'hidden',
      }} className="register-left-panel">
        <style>{`
          @media (min-width: 1024px) {
            .register-left-panel { display: flex !important; }
          }
        `}</style>

        {/* Ambient glows */}
        <div style={{ position: 'absolute', top: '-5%', left: '-5%', width: 500, height: 500, borderRadius: '50%', background: 'rgba(124, 58, 237, 0.1)', filter: 'blur(120px)', pointerEvents: 'none' }} />
        <div style={{ position: 'absolute', bottom: 0, right: 0, width: 400, height: 400, borderRadius: '50%', background: 'rgba(99, 102, 241, 0.06)', filter: 'blur(100px)', pointerEvents: 'none' }} />
        
        {/* Grid pattern */}
        <div style={{
          position: 'absolute', inset: 0,
          backgroundImage: 'linear-gradient(to right, rgba(30,41,59,0.08) 1px, transparent 1px), linear-gradient(to bottom, rgba(30,41,59,0.08) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
          pointerEvents: 'none',
        }} />

        {/* Logo */}
        <div style={{ position: 'relative', zIndex: 10, display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 40, height: 40, borderRadius: 12,
            background: 'linear-gradient(135deg, #6366f1, #7c3aed)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 4px 16px rgba(99,102,241,0.3)',
          }}>
            <Shield size={20} color="white" />
          </div>
          <span style={{ fontSize: 20, fontWeight: 900, color: 'white', letterSpacing: '-0.5px' }}>
            Audit<span style={{ color: '#818cf8' }}>Shield</span>
          </span>
        </div>

        {/* Center content */}
        <div style={{ position: 'relative', zIndex: 10, display: 'flex', flexDirection: 'column', gap: 32 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 8, fontSize: 11, fontWeight: 700,
              textTransform: 'uppercase', letterSpacing: '0.12em', color: '#a78bfa',
              background: 'rgba(167, 139, 250, 0.08)', border: '1px solid rgba(167, 139, 250, 0.2)',
              padding: '4px 12px', borderRadius: 9999, width: 'fit-content',
            }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#a78bfa', animation: 'pulse 2s infinite' }} />
              Registro gratuito
            </span>
            <h1 style={{ fontSize: 36, fontWeight: 900, color: 'white', letterSpacing: '-1px', lineHeight: 1.15, margin: 0 }}>
              Únete a la<br />
              <span style={{ background: 'linear-gradient(90deg, #a78bfa, #818cf8, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                plataforma
              </span>
            </h1>
            <p style={{ fontSize: 14, color: '#94a3b8', maxWidth: 320, lineHeight: 1.6, margin: 0 }}>
              Crea tu cuenta y comienza a auditar dominios, redes e infraestructura en minutos.
            </p>
          </div>

          {/* Benefits */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[
              'Auditorías con perfiles OWASP, NIST e ISO 27001',
              'Reportes PDF ejecutivos generados automáticamente',
              'Consola de auditoría con logs en tiempo real',
            ].map((text, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 13, color: '#cbd5e1', animation: `fadeInUp 0.4s ease ${i * 0.15}s both` }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 8,
                  background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                }}>
                  <CheckCircle2 size={14} color="#818cf8" />
                </div>
                {text}
              </div>
            ))}
          </div>

          {/* Terminal preview */}
          <div style={{
            background: 'rgba(0, 0, 0, 0.4)',
            border: '1px solid rgba(255,255,255,0.06)',
            borderRadius: 16,
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '10px 16px',
              background: 'rgba(255,255,255,0.02)',
              borderBottom: '1px solid rgba(255,255,255,0.04)',
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <div style={{ display: 'flex', gap: 6 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#eab308' }} />
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e' }} />
              </div>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#475569' }}>auditshield@engine:~</span>
            </div>
            <div ref={terminalRef} style={{ padding: 16, maxHeight: 180, overflowY: 'auto', fontFamily: '"JetBrains Mono", monospace', fontSize: 11, lineHeight: 1.6 }}>
              {terminalLines.map((line, i) => (
                <div key={i} style={{ color: line && line.startsWith('$') ? '#22d3ee' : line && line.startsWith('[✓]') ? '#34d399' : '#94a3b8' }}>
                  {line}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{ position: 'relative', zIndex: 10, fontSize: 11, color: '#334155', fontFamily: 'monospace', letterSpacing: '0.1em' }}>
          PROYECTO DE TITULO — AUDITSHIELD 2026
        </div>
      </div>

      {/* ── RIGHT PANEL (Register Form) ── */}
      <div style={{
        flex: 1,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '40px 24px',
        position: 'relative',
      }}>
        {/* Vertical divider */}
        <div className="register-left-panel" style={{
          position: 'absolute', left: 0, top: 48, bottom: 48, width: 1,
          background: 'linear-gradient(to bottom, transparent, #1e293b, transparent)',
          display: 'none',
        }} />

        <div style={{ width: '100%', maxWidth: 420, display: 'flex', flexDirection: 'column', gap: 20, animation: 'fadeInUp 0.5s ease' }}>

          {/* Mobile logo */}
          <div className="register-mobile-logo" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <style>{`
              @media (min-width: 1024px) {
                .register-mobile-logo { display: none !important; }
              }
            `}</style>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg, #6366f1, #7c3aed)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Shield size={16} color="white" />
            </div>
            <span style={{ fontSize: 18, fontWeight: 900, color: 'white' }}>Audit<span style={{ color: '#818cf8' }}>Shield</span></span>
          </div>

          <div>
            <h2 style={{ fontSize: 24, fontWeight: 900, color: 'white', letterSpacing: '-0.5px', margin: 0 }}>Crear Cuenta</h2>
            <p style={{ fontSize: 14, color: '#64748b', margin: '4px 0 0' }}>Regístrate como auditor en segundos</p>
          </div>

          {/* Glass card */}
          <div style={{
            background: 'rgba(255, 255, 255, 0.025)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            backdropFilter: 'blur(24px)',
            borderRadius: 20,
            padding: 28,
            boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4)',
          }}>
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

              {/* Full name */}
              <div>
                <label style={labelStyle}>Nombre Completo</label>
                <div style={{ position: 'relative' }}>
                  <UserCircle size={16} style={iconStyle} />
                  <input
                    name="full_name" type="text" placeholder="Juan Pérez"
                    value={form.full_name} onChange={handleChange}
                    className="reg-input" style={inputStyle}
                  />
                </div>
              </div>

              {/* Email */}
              <div>
                <label style={labelStyle}>Correo Electrónico</label>
                <div style={{ position: 'relative' }}>
                  <Mail size={16} style={iconStyle} />
                  <input
                    name="email" type="email" placeholder="nombre@empresa.com"
                    value={form.email} onChange={handleChange}
                    className="reg-input" style={inputStyle}
                  />
                </div>
              </div>

              {/* Username */}
              <div>
                <label style={labelStyle}>Usuario</label>
                <div style={{ position: 'relative' }}>
                  <User size={16} style={iconStyle} />
                  <input
                    name="username" type="text" placeholder="jperez"
                    value={form.username} onChange={handleChange}
                    className="reg-input" style={inputStyle}
                  />
                </div>
              </div>

              {/* Password row */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={labelStyle}>Contraseña</label>
                  <div style={{ position: 'relative' }}>
                    <Lock size={16} style={iconStyle} />
                    <input
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Min. 8 chars"
                      value={form.password} onChange={handleChange}
                      className="reg-input" style={{ ...inputStyle, paddingRight: 36 }}
                    />
                    <button type="button" onClick={() => setShowPassword(!showPassword)}
                      style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', display: 'flex', padding: 0 }}>
                      {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>

                <div>
                  <label style={labelStyle}>Confirmar</label>
                  <div style={{ position: 'relative' }}>
                    <Lock size={16} style={iconStyle} />
                    <input
                      name="confirmPassword"
                      type={showConfirm ? 'text' : 'password'}
                      placeholder="Repite"
                      value={form.confirmPassword} onChange={handleChange}
                      className="reg-input" style={{ ...inputStyle, paddingRight: 36 }}
                    />
                    <button type="button" onClick={() => setShowConfirm(!showConfirm)}
                      style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', display: 'flex', padding: 0 }}>
                      {showConfirm ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Password strength */}
              {form.password.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  {[1, 2, 3, 4].map(n => (
                    <div key={n} style={{
                      height: 4, flex: 1, borderRadius: 2,
                      background: passwordStrength >= n ? strengthColors[Math.min(passwordStrength - 1, 3)] : 'rgba(255,255,255,0.06)',
                      transition: 'background 0.3s',
                    }} />
                  ))}
                  <span style={{ fontSize: 10, color: '#64748b', marginLeft: 4, whiteSpace: 'nowrap' }}>
                    {strengthLabels[Math.min(passwordStrength - 1, 3)] || 'Muy débil'}
                  </span>
                </div>
              )}

              {/* Error */}
              {error && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: 12,
                  background: 'rgba(239, 68, 68, 0.06)',
                  border: '1px solid rgba(239, 68, 68, 0.2)',
                  borderRadius: 12,
                  fontSize: 12, color: '#fca5a5',
                }}>
                  <AlertCircle size={16} style={{ flexShrink: 0 }} />
                  <span>{error}</span>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                style={{
                  width: '100%',
                  padding: '14px 20px',
                  borderRadius: 14,
                  background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
                  border: 'none',
                  color: 'white',
                  fontSize: 14,
                  fontWeight: 700,
                  cursor: loading ? 'wait' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 8,
                  boxShadow: '0 4px 20px rgba(79, 70, 229, 0.35)',
                  transition: 'all 0.2s',
                  opacity: loading ? 0.7 : 1,
                  marginTop: 4,
                  position: 'relative',
                  overflow: 'hidden',
                }}
                onMouseEnter={e => { if (!loading) e.currentTarget.style.boxShadow = '0 8px 28px rgba(79, 70, 229, 0.5)'; }}
                onMouseLeave={e => { e.currentTarget.style.boxShadow = '0 4px 20px rgba(79, 70, 229, 0.35)'; }}
              >
                {loading ? (
                  <><Loader2 size={16} className="animate-spin" /> Creando cuenta...</>
                ) : (
                  <><Shield size={16} /> Crear Cuenta <ArrowRight size={16} /></>
                )}
              </button>
            </form>
          </div>

          {/* Login link */}
          <p style={{ textAlign: 'center', fontSize: 13, color: '#64748b', margin: 0 }}>
            ¿Ya tienes cuenta?{' '}
            <Link href="/login" style={{ color: '#818cf8', fontWeight: 700, textDecoration: 'none' }}>
              Inicia sesión aquí
            </Link>
          </p>

          {/* Trust badges */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 20 }}>
            {['TLS 1.3', 'JWT Auth', 'OWASP'].map((badge) => (
              <div key={badge} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, color: '#334155', fontFamily: 'monospace' }}>
                <CheckCircle2 size={12} color="#065f46" />
                {badge}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
