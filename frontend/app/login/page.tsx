'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Shield, Mail, Lock, Eye, EyeOff, Loader2, AlertCircle, Zap, ArrowRight, Terminal, CheckCircle2, Activity } from 'lucide-react';
import toast from 'react-hot-toast';
import { motion, AnimatePresence } from 'framer-motion';
import { authApi } from '@/lib/api';
import { useAuthStore } from '@/lib/store';

const DEMO_USER = {
  id: 1,
  username: 'demo',
  email: 'demo@auditshield.cl',
  full_name: 'Usuario Demo',
  role: 'analyst',
  is_active: true,
  organization_id: 1,
  created_at: new Date().toISOString(),
};

const TERMINAL_LINES = [
  { delay: 0,    text: '$ auditshield init --target liceotecnico.cl', type: 'cmd' },
  { delay: 900,  text: '[OK] Módulos cargados: osint, dns, ssl, web',  type: 'ok' },
  { delay: 1800, text: '$ nmap -sV -T4 -p 80,443 liceotecnico.cl',    type: 'cmd' },
  { delay: 2700, text: '80/tcp  open  http   nginx 1.24.0',            type: 'out' },
  { delay: 3600, text: '443/tcp open  ssl/https (TLS 1.3)',            type: 'out' },
  { delay: 4500, text: '$ dig TXT _dmarc.liceotecnico.cl +short',     type: 'cmd' },
  { delay: 5400, text: '[WARN] DMARC not found. Risk: HIGH',           type: 'warn' },
  { delay: 6300, text: '[DONE] Score: 68/100 — Grade: C+',            type: 'done' },
];

export default function LoginPage() {
  const router = useRouter();
  const { setToken, setUser } = useAuthStore();

  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');
  const [visibleLines, setVisibleLines] = useState<number[]>([]);

  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    TERMINAL_LINES.forEach((line, i) => {
      timers.push(setTimeout(() => setVisibleLines(prev => [...prev, i]), line.delay));
    });
    return () => timers.forEach(clearTimeout);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) { setError('Completa todos los campos.'); return; }
    setError(''); setLoading(true);
    try {
      const data = await authApi.login(email, password);
      setToken(data.access_token);
      setUser(data.user);
      toast.success(`¡Bienvenido, ${data.user.full_name || data.user.username}!`);
      router.push('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Credenciales inválidas.');
    } finally { setLoading(false); }
  };

  const handleDemoLogin = () => {
    setToken('demo-token-auditshield-2024');
    setUser(DEMO_USER as any);
    toast.success('Acceso Demo concedido');
    router.push('/dashboard');
  };

  const termColor = (type: string) => {
    if (type === 'cmd')  return '#4ade80';
    if (type === 'ok')   return '#38bdf8';
    if (type === 'warn') return '#fbbf24';
    if (type === 'done') return '#a78bfa';
    return '#94a3b8';
  };

  return (
    <div style={{ display:'flex', minHeight:'100vh', background:'#020817', overflow:'hidden' }}>

      {/* ── LEFT PANEL ── */}
      <div className="login-left-panel">
        {/* Background effects */}
        <div style={{ position:'absolute', inset:0, pointerEvents:'none', overflow:'hidden' }}>
          <div style={{ position:'absolute', top:'-10%', left:'-10%', width:600, height:600, borderRadius:'50%', background:'radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%)', filter:'blur(40px)' }} />
          <div style={{ position:'absolute', bottom:'-10%', right:'-5%', width:500, height:500, borderRadius:'50%', background:'radial-gradient(circle, rgba(139,92,246,0.10) 0%, transparent 70%)', filter:'blur(40px)' }} />
          {/* Grid lines */}
          <div style={{ position:'absolute', inset:0, backgroundImage:'linear-gradient(rgba(30,41,59,0.18) 1px, transparent 1px), linear-gradient(90deg, rgba(30,41,59,0.18) 1px, transparent 1px)', backgroundSize:'32px 32px' }} />
        </div>

        {/* Logo */}
        <div style={{ position:'relative', zIndex:1, display:'flex', alignItems:'center', gap:12 }}>
          <div style={{ width:42, height:42, borderRadius:12, background:'linear-gradient(135deg, #6366f1, #8b5cf6)', display:'flex', alignItems:'center', justifyContent:'center', boxShadow:'0 0 24px rgba(99,102,241,0.4)' }}>
            <Shield size={20} color="white" />
          </div>
          <span style={{ fontSize:22, fontWeight:900, color:'white', letterSpacing:'-0.5px' }}>
            Audit<span style={{ color:'#818cf8' }}>Shield</span>
          </span>
        </div>

        {/* Headline */}
        <div style={{ position:'relative', zIndex:1, display:'flex', flexDirection:'column', gap:32 }}>
          <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
            <div style={{ display:'inline-flex', alignItems:'center', gap:8, fontSize:11, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'#818cf8', background:'rgba(99,102,241,0.1)', border:'1px solid rgba(99,102,241,0.25)', padding:'4px 12px', borderRadius:9999, width:'fit-content' }}>
              <span style={{ width:7, height:7, borderRadius:'50%', background:'#818cf8', animation:'pulse 2s ease-in-out infinite' }} />
              Plataforma activa
            </div>
            <h1 style={{ fontSize:40, fontWeight:900, color:'white', lineHeight:1.15, letterSpacing:'-1px', margin:0 }}>
              Ciberseguridad<br />
              <span style={{ background:'linear-gradient(90deg, #818cf8, #a78bfa, #38bdf8)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>
                a nivel profesional
              </span>
            </h1>
            <p style={{ fontSize:14, color:'#94a3b8', lineHeight:1.6, maxWidth:340, margin:0 }}>
              Analiza, detecta y reporta vulnerabilidades mediante auditorías automáticas de sistemas web.
            </p>
          </div>

          {/* Terminal window */}
          <div style={{ background:'rgba(4,13,26,0.9)', border:'1px solid #1e293b', borderRadius:16, overflow:'hidden', boxShadow:'0 24px 48px rgba(0,0,0,0.6)' }}>
            {/* Terminal top bar */}
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'10px 16px', background:'rgba(10,22,40,0.8)', borderBottom:'1px solid #1e293b' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <div style={{ display:'flex', gap:6 }}>
                  <div style={{ width:11, height:11, borderRadius:'50%', background:'rgba(239,68,68,0.6)', border:'1px solid rgba(239,68,68,0.4)' }} />
                  <div style={{ width:11, height:11, borderRadius:'50%', background:'rgba(245,158,11,0.6)', border:'1px solid rgba(245,158,11,0.4)' }} />
                  <div style={{ width:11, height:11, borderRadius:'50%', background:'rgba(34,197,94,0.6)', border:'1px solid rgba(34,197,94,0.4)' }} />
                </div>
                <div style={{ display:'flex', alignItems:'center', gap:6, marginLeft:8 }}>
                  <Terminal size={12} color="#475569" />
                  <span style={{ fontSize:11, fontFamily:'monospace', color:'#475569' }}>auditshield — scan session</span>
                </div>
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                <span style={{ width:6, height:6, borderRadius:'50%', background:'#4ade80', display:'inline-block', animation:'pulse 1.5s ease-in-out infinite' }} />
                <span style={{ fontSize:10, fontFamily:'monospace', color:'#475569' }}>LIVE</span>
              </div>
            </div>
            {/* Terminal body */}
            <div style={{ padding:'16px 20px', minHeight:200, display:'flex', flexDirection:'column', gap:6 }}>
              {TERMINAL_LINES.map((line, i) =>
                visibleLines.includes(i) ? (
                  <motion.div
                    key={i}
                    initial={{ opacity:0, x:-8 }}
                    animate={{ opacity:1, x:0 }}
                    transition={{ duration:0.2 }}
                    style={{ display:'flex', gap:8, fontFamily:'monospace', fontSize:12, color: termColor(line.type) }}
                  >
                    <span style={{ color:'#334155', userSelect:'none', flexShrink:0 }}>{line.type === 'cmd' ? '❯' : ' '}</span>
                    <span>{line.text}</span>
                  </motion.div>
                ) : null
              )}
              <motion.span
                animate={{ opacity:[1,0,1] }}
                transition={{ repeat:Infinity, duration:0.9 }}
                style={{ display:'inline-block', width:8, height:14, background:'#4ade80', marginTop:4, borderRadius:1 }}
              />
            </div>
          </div>

          {/* Stats */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
            {[
              { label:'Vulns detectadas', value:'2,841', icon: Activity },
              { label:'Reportes PDF',     value:'198',   icon: CheckCircle2 },
              { label:'Dominios',         value:'94',    icon: Shield },
            ].map((s) => (
              <div key={s.label} style={{ background:'rgba(255,255,255,0.02)', border:'1px solid rgba(255,255,255,0.06)', borderRadius:14, padding:'14px 12px', display:'flex', flexDirection:'column', gap:6 }}>
                <s.icon size={16} color="#818cf8" />
                <p style={{ fontSize:22, fontWeight:900, color:'white', margin:0 }}>{s.value}</p>
                <p style={{ fontSize:10, color:'#64748b', margin:0, lineHeight:1.3 }}>{s.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div style={{ position:'relative', zIndex:1, fontSize:10, color:'#334155', fontFamily:'monospace', letterSpacing:'0.12em' }}>
          PROYECTO DE TITULO — AUDITSHIELD 2026
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', padding:'40px 24px', position:'relative' }}>
        {/* Separator */}
        <div style={{ position:'absolute', left:0, top:48, bottom:48, width:1, background:'linear-gradient(to bottom, transparent, #1e293b, transparent)' }} />

        <motion.div
          initial={{ opacity:0, y:24 }}
          animate={{ opacity:1, y:0 }}
          transition={{ duration:0.5, ease:'easeOut' }}
          style={{ width:'100%', maxWidth:400, display:'flex', flexDirection:'column', gap:24 }}
        >
          {/* Header */}
          <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
            <h2 style={{ fontSize:28, fontWeight:900, color:'white', letterSpacing:'-0.5px', margin:0 }}>Iniciar Sesión</h2>
            <p style={{ fontSize:14, color:'#64748b', margin:0 }}>Accede a tus proyectos de seguridad</p>
          </div>

          {/* Card */}
          <div style={{ background:'rgba(255,255,255,0.025)', border:'1px solid rgba(255,255,255,0.08)', backdropFilter:'blur(20px)', borderRadius:20, padding:28, boxShadow:'0 24px 48px rgba(0,0,0,0.4)', display:'flex', flexDirection:'column', gap:20 }}>
            <form onSubmit={handleSubmit} style={{ display:'flex', flexDirection:'column', gap:16 }}>

              {/* Email */}
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <label htmlFor="email" style={{ fontSize:11, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'#64748b' }}>
                  Correo Electrónico
                </label>
                <div style={{ position:'relative' }}>
                  <Mail size={16} color="#475569" style={{ position:'absolute', left:14, top:'50%', transform:'translateY(-50%)', pointerEvents:'none' }} />
                  <input
                    id="email" type="email" placeholder="nombre@empresa.com"
                    value={email} onChange={e => setEmail(e.target.value)} autoComplete="email"
                    style={{ width:'100%', background:'rgba(2,8,23,0.8)', border:'1px solid #1e293b', borderRadius:12, padding:'12px 16px 12px 42px', fontSize:14, color:'#e2e8f0', outline:'none', transition:'border-color 0.2s', fontFamily:'Inter, sans-serif', boxSizing:'border-box' }}
                    onFocus={e => e.target.style.borderColor = 'rgba(99,102,241,0.6)'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  />
                </div>
              </div>

              {/* Password */}
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                  <label htmlFor="password" style={{ fontSize:11, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'#64748b' }}>
                    Contraseña
                  </label>
                  <span style={{ fontSize:11, color:'#818cf8', cursor:'pointer' }}>¿Olvidaste tu contraseña?</span>
                </div>
                <div style={{ position:'relative' }}>
                  <Lock size={16} color="#475569" style={{ position:'absolute', left:14, top:'50%', transform:'translateY(-50%)', pointerEvents:'none' }} />
                  <input
                    id="password" type={showPass ? 'text' : 'password'} placeholder="••••••••"
                    value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password"
                    style={{ width:'100%', background:'rgba(2,8,23,0.8)', border:'1px solid #1e293b', borderRadius:12, padding:'12px 44px 12px 42px', fontSize:14, color:'#e2e8f0', outline:'none', transition:'border-color 0.2s', fontFamily:'Inter, sans-serif', boxSizing:'border-box' }}
                    onFocus={e => e.target.style.borderColor = 'rgba(99,102,241,0.6)'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  />
                  <button type="button" onClick={() => setShowPass(!showPass)}
                    style={{ position:'absolute', right:14, top:'50%', transform:'translateY(-50%)', background:'none', border:'none', cursor:'pointer', color:'#475569', display:'flex', alignItems:'center', padding:0 }}>
                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* Error */}
              <AnimatePresence>
                {error && (
                  <motion.div
                    initial={{ opacity:0, height:0 }} animate={{ opacity:1, height:'auto' }} exit={{ opacity:0, height:0 }}
                    style={{ display:'flex', alignItems:'center', gap:10, padding:'10px 14px', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.25)', borderRadius:12, color:'#fca5a5', fontSize:13, overflow:'hidden' }}
                  >
                    <AlertCircle size={15} style={{ flexShrink:0 }} />
                    <span>{error}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Submit */}
              <button type="submit" disabled={loading}
                style={{ width:'100%', padding:'13px', background:'linear-gradient(135deg, #4f46e5, #7c3aed)', border:'none', borderRadius:12, color:'white', fontSize:14, fontWeight:700, cursor: loading ? 'not-allowed' : 'pointer', opacity: loading ? 0.7 : 1, display:'flex', alignItems:'center', justifyContent:'center', gap:8, transition:'all 0.2s', boxShadow:'0 4px 24px rgba(79,70,229,0.3)', fontFamily:'Inter, sans-serif' }}
                onMouseEnter={e => { if(!loading) (e.currentTarget.style.boxShadow = '0 8px 32px rgba(79,70,229,0.5)'); }}
                onMouseLeave={e => { (e.currentTarget.style.boxShadow = '0 4px 24px rgba(79,70,229,0.3)'); }}
              >
                {loading ? <><Loader2 size={16} className="animate-spin" />Autenticando...</> : <><Shield size={16} />Iniciar Sesión<ArrowRight size={16} /></>}
              </button>
            </form>

            {/* Divider */}
            <div style={{ display:'flex', alignItems:'center', gap:12 }}>
              <div style={{ flex:1, height:1, background:'rgba(255,255,255,0.06)' }} />
              <span style={{ fontSize:10, fontWeight:700, letterSpacing:'0.1em', textTransform:'uppercase', color:'#334155' }}>o</span>
              <div style={{ flex:1, height:1, background:'rgba(255,255,255,0.06)' }} />
            </div>

            {/* Demo button */}
            <button type="button" onClick={handleDemoLogin}
              style={{ width:'100%', padding:'12px', background:'rgba(245,158,11,0.06)', border:'1px solid rgba(245,158,11,0.2)', borderRadius:12, color:'#fbbf24', fontSize:14, fontWeight:600, cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center', gap:10, transition:'all 0.2s', fontFamily:'Inter, sans-serif' }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(245,158,11,0.12)'; e.currentTarget.style.borderColor = 'rgba(245,158,11,0.35)'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(245,158,11,0.06)'; e.currentTarget.style.borderColor = 'rgba(245,158,11,0.2)'; }}
            >
              <Zap size={16} />
              Entrar en Modo Demo
              <span style={{ fontSize:11, color:'#92400e', fontWeight:400 }}>(sin backend)</span>
            </button>
          </div>

          {/* Register link */}
          <p style={{ textAlign:'center', fontSize:13, color:'#475569', margin:0 }}>
            ¿No tienes cuenta?{' '}
            <Link href="/register" style={{ color:'#818cf8', fontWeight:600, textDecoration:'none' }}>
              Créate una aquí
            </Link>
          </p>

          {/* Trust badges */}
          <div style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:24 }}>
            {['TLS 1.3', 'JWT Auth', 'OWASP'].map(b => (
              <div key={b} style={{ display:'flex', alignItems:'center', gap:5, fontSize:10, color:'#334155', fontFamily:'monospace' }}>
                <CheckCircle2 size={11} color="#166534" />
                {b}
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Responsive styles */}
      <style>{`
        .login-left-panel {
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          padding: 48px;
          position: relative;
          overflow: hidden;
          width: 55%;
          flex-shrink: 0;
        }
        @media (max-width: 1024px) {
          .login-left-panel { display: none; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
      `}</style>
    </div>
  );
}
