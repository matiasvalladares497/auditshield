'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { 
  ArrowLeft, 
  ArrowRight, 
  Rocket, 
  Globe, 
  Cpu, 
  ShieldAlert, 
  FileText,
  Check,
  Settings as SettingsIcon,
  ToggleLeft,
  ToggleRight,
  Mail,
  Eye,
  ClipboardCheck,
  Network
} from 'lucide-react';
import { auditsApi, assetsApi, type Asset } from '@/lib/api';
import toast from 'react-hot-toast';

export default function NewAuditPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [assets, setAssets] = useState<Asset[]>([]);
  
  // Form State
  const [title, setTitle] = useState('');
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('domain');
  const [profile, setProfile] = useState('full'); // basic, web, infrastructure, full, custom
  const [assetId, setAssetId] = useState<number | null>(null);
  
  // Custom Modules State
  const [modules, setModules] = useState<Record<string, boolean>>({
    osint: true,
    port_scan: true,
    ssl: true,
    web: true,
    dns: true,
    email_security: true,
    info_exposure: true,
    cve_matching: true,
    waf_detection: true,
    compliance: true,
  });

  // Advanced Options
  const [intensity, setIntensity] = useState('normal'); // stealth, normal, aggressive
  const [portRange, setPortRange] = useState('1-1000');
  const [autoGeneratePdf, setAutoGeneratePdf] = useState(true);

  useEffect(() => {
    assetsApi.list()
      .then(setAssets)
      .catch(() => console.log('Error cargando activos'));
  }, []);

  const handleAssetChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value;
    if (val === '') {
      setAssetId(null);
      return;
    }
    const id = parseInt(val);
    const selected = assets.find(a => a.id === id);
    if (selected) {
      setAssetId(id);
      setTarget(selected.target);
      setTargetType(selected.asset_type);
      if (!title) {
        setTitle(`Auditoría de ${selected.name}`);
      }
    }
  };

  const toggleModule = (key: string) => {
    setModules(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleNextStep = () => {
    if (step === 1) {
      if (!title.trim() || !target.trim()) {
        toast.error('Por favor ingresa un título y un objetivo (dominio/IP)');
        return;
      }
    }
    setStep(prev => prev + 1);
  };

  const handlePrevStep = () => {
    setStep(prev => prev - 1);
  };

  const handleSubmit = async () => {
    const payload = {
      title,
      target,
      target_type: targetType,
      profile,
      modules,
      scan_options: {
        intensity,
        port_range: portRange,
        auto_generate_pdf: autoGeneratePdf
      },
      asset_id: assetId
    };

    try {
      const res = await auditsApi.create(payload);
      toast.success('Auditoría programada con éxito.');
      router.push(`/dashboard/audits/${res.id}`);
    } catch (error) {
      toast.error('Error al iniciar la auditoría de seguridad.');
    }
  };

  // Styles Definitions for Premium Look
  const glassCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.025)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(24px)',
    borderRadius: 20,
    padding: 32,
    boxShadow: '0 24px 48px rgba(0, 0, 0, 0.4)',
    minHeight: 380,
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
  };

  const inputStyle = {
    width: '100%',
    background: 'rgba(2, 8, 23, 0.8)',
    border: '1px solid #1e293b',
    borderRadius: 12,
    padding: '12px 16px',
    fontSize: 14,
    color: '#e2e8f0',
    outline: 'none',
    transition: 'border-color 0.2s',
    fontFamily: 'Inter, sans-serif',
    boxSizing: 'border-box' as const,
  };

  const labelStyle: React.CSSProperties = {
    fontSize: 11,
    fontWeight: 700,
    letterSpacing: '0.1em',
    textTransform: 'uppercase',
    color: '#64748b',
    display: 'block',
    marginBottom: 6,
  };

  const stepColor = (s: number) => {
    if (step === s) return '#818cf8'; // Active (indigo)
    if (step > s) return '#34d399'; // Completed (emerald)
    return '#1e293b'; // Pending
  };

  // Profile Card Component
  const renderProfileCard = (id: string, titleStr: string, desc: string, Icon: React.ComponentType<any>, color: string) => {
    const isSelected = profile === id;
    return (
      <div
        onClick={() => setProfile(id)}
        style={{
          padding: 16,
          borderRadius: 14,
          border: isSelected ? `1px solid ${color}` : '1px solid #1e293b',
          background: isSelected ? `${color}06` : 'rgba(255, 255, 255, 0.01)',
          cursor: 'pointer',
          transition: 'all 0.3s',
          display: 'flex',
          alignItems: 'start',
          gap: 12,
          boxShadow: isSelected ? `0 4px 20px ${color}10` : 'none',
        }}
        onMouseEnter={e => {
          if (!isSelected) {
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.2)';
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)';
          }
        }}
        onMouseLeave={e => {
          if (!isSelected) {
            e.currentTarget.style.borderColor = '#1e293b';
            e.currentTarget.style.background = 'rgba(255, 255, 255, 0.01)';
          }
        }}
      >
        <div style={{
          padding: 8,
          borderRadius: 8,
          background: isSelected ? `${color}1a` : 'rgba(255, 255, 255, 0.04)',
          color: isSelected ? color : '#64748b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={16} />
        </div>
        <div style={{ textAlign: 'left' }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: '#f1f5f9', margin: 0 }}>{titleStr}</h4>
          <p style={{ fontSize: 11, color: '#94a3b8', margin: '4px 0 0', lineHeight: 1.4 }}>{desc}</p>
        </div>
      </div>
    );
  };

  return (
    <div style={{ maxWidth: 800, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 32 }}>
      
      {/* Header and Step Indicators */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 900, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
            Programar Auditoría
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4, margin: '4px 0 0' }}>
            Configura el objetivo y alcance de las pruebas de seguridad.
          </p>
        </div>
        
        {/* Step Indicator Badges (Interactive Timeline) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {[1, 2, 3, 4].map((s) => (
            <div key={s} style={{ display: 'flex', alignItems: 'center' }}>
              {s > 1 && (
                <div style={{
                  width: 24,
                  height: 1,
                  background: step >= s ? '#818cf8' : '#1e293b',
                  transition: 'background 0.3s',
                  marginRight: 8,
                }} />
              )}
              <div
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: '50%',
                  border: `1px solid ${stepColor(s)}`,
                  background: step === s ? 'rgba(129, 140, 248, 0.15)' : step > s ? 'rgba(52, 211, 153, 0.1)' : 'rgba(0,0,0,0.2)',
                  color: stepColor(s),
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 700,
                  fontSize: 12,
                  fontFamily: 'monospace',
                  transition: 'all 0.3s',
                  boxShadow: step === s ? '0 0 16px rgba(129, 140, 248, 0.2)' : 'none',
                }}
              >
                {step > s ? <Check size={14} /> : s}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={glassCardStyle}>
        
        {/* STEP 1: OBJETIVO */}
        {step === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <h3 style={{ fontSize: 14, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#818cf8', margin: 0 }}>
              Paso 1: Definir Objetivo
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              
              {/* Asociar activo */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={labelStyle}>Asociar Activo Existente (Opcional)</label>
                <select
                  onChange={handleAssetChange}
                  value={assetId || ''}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                >
                  <option value="" style={{ background: '#020817' }}>-- No asociar activo (Ingreso Manual) --</option>
                  {assets.map((asset) => (
                    <option key={asset.id} value={asset.id} style={{ background: '#020817' }}>
                      {asset.name} ({asset.target})
                    </option>
                  ))}
                </select>
              </div>

              {/* Título */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={labelStyle}>Título de la Auditoría</label>
                <input
                  type="text"
                  placeholder="Ej: Auditoría del Sitio Web Escolar v2"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                />
              </div>

              {/* Grid 2 columns for Target and Type */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                {/* Objetivo (Target) */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={labelStyle}>Objetivo (Target)</label>
                  <input
                    type="text"
                    placeholder="Ej: liceotecnico.cl o 192.168.1.1"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    style={inputStyle}
                    onFocus={e => e.target.style.borderColor = '#818cf8'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  />
                </div>

                {/* Tipo de target */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={labelStyle}>Tipo de Objetivo</label>
                  <select
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    style={inputStyle}
                    onFocus={e => e.target.style.borderColor = '#818cf8'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  >
                    <option value="domain" style={{ background: '#020817' }}>Dominio o Subdominio (Domain)</option>
                    <option value="ip" style={{ background: '#020817' }}>Dirección IP Estática (IP)</option>
                    <option value="url" style={{ background: '#020817' }}>Dirección URL Web (URL)</option>
                    <option value="cidr" style={{ background: '#020817' }}>Rango de Red (CIDR)</option>
                  </select>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* STEP 2: PERFIL DE ESCANEO */}
        {step === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <h3 style={{ fontSize: 14, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#818cf8', margin: 0 }}>
              Paso 2: Perfil de Escaneo
            </h3>
            
            {/* Grid de perfiles */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
              {renderProfileCard('full', 'Perfil Completo (Full)', 'Reconocimiento OSINT, puertos, SSL, OWASP y CVEs. (Recomendado)', Globe, '#6366f1')}
              {renderProfileCard('web', 'Aplicación Web (OWASP)', 'OWASP Top 10, cookies, headers HTTP y exposición de archivos.', FileText, '#a78bfa')}
              {renderProfileCard('infrastructure', 'Infraestructura & Puertos', 'Puertos abiertos, banners de servicios y registros DNS.', Cpu, '#22d3ee')}
              {renderProfileCard('email_dns', 'Seguridad Email & DNS', 'SPF, DKIM, DMARC y análisis de zona DNS. Evita phishing.', Mail, '#f59e0b')}
              {renderProfileCard('osint_leak', 'OSINT & Filtraciones', 'Credenciales expuestas, Shodan, GitHub leaks y Pastebin.', Eye, '#f43f5e')}
              {renderProfileCard('compliance_chk', 'Cumplimiento ISO/NIST', 'Verifica controles de ISO 27001, NIST CSF y marcos de seguridad.', ClipboardCheck, '#10b981')}
              {renderProfileCard('lan_internal', 'Red Interna (LAN/CIDR)', 'Escaneo CIDR interno, ARP discovery y segmentación.', Network, '#f97316')}
              {renderProfileCard('custom', 'Personalizado (Custom)', 'Activa y desactiva de manera individual los módulos que desees.', SettingsIcon, '#94a3b8')}
            </div>

            {/* Custom Modules Grid */}
            {profile === 'custom' && (
              <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
                <label style={labelStyle}>Módulos Disponibles</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                  {Object.keys(modules).map((key) => (
                    <div
                      key={key}
                      onClick={() => toggleModule(key)}
                      style={{
                        padding: 12,
                        borderRadius: 10,
                        border: modules[key] ? '1px solid rgba(99,102,241,0.25)' : '1px solid #1e293b',
                        background: modules[key] ? 'rgba(99,102,241,0.04)' : 'rgba(0,0,0,0.1)',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        fontSize: 11,
                        fontWeight: 600,
                        color: modules[key] ? '#c7d2fe' : '#64748b',
                        transition: 'all 0.2s',
                      }}
                    >
                      <span style={{ textTransform: 'capitalize' }}>{key.replace('_', ' ')}</span>
                      {modules[key] ? <ToggleRight size={20} color="#818cf8" /> : <ToggleLeft size={20} color="#475569" />}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* STEP 3: OPCIONES AVANZADAS */}
        {step === 3 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <h3 style={{ fontSize: 14, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#818cf8', margin: 0 }}>
              Paso 3: Opciones Avanzadas
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                
                {/* Intensidad */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={labelStyle}>Intensidad del Escaneo</label>
                  <select
                    value={intensity}
                    onChange={(e) => setIntensity(e.target.value)}
                    style={inputStyle}
                    onFocus={e => e.target.style.borderColor = '#818cf8'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  >
                    <option value="stealth" style={{ background: '#020817' }}>Silencioso / Sigiloso (Stealth)</option>
                    <option value="normal" style={{ background: '#020817' }}>Normal (Recomendado)</option>
                    <option value="aggressive" style={{ background: '#020817' }}>Agresivo / Intrusivo (Aggressive)</option>
                  </select>
                  <p style={{ fontSize: 10, color: '#475569', margin: '4px 0 0' }}>
                    Agresivo tiene mayor probabilidad de activar firewalls/WAFs pero recoge más banners.
                  </p>
                </div>

                {/* Rango de puertos */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={labelStyle}>Rango de Puertos TCP</label>
                  <input
                    type="text"
                    value={portRange}
                    onChange={(e) => setPortRange(e.target.value)}
                    placeholder="Ej: 1-1000, 80,443"
                    style={inputStyle}
                    onFocus={e => e.target.style.borderColor = '#818cf8'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  />
                  <p style={{ fontSize: 10, color: '#475569', margin: '4px 0 0' }}>
                    Ingrese un rango o valores separados por comas. Default: 1-1000.
                  </p>
                </div>

              </div>

              {/* Auto PDF Toggle */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 10 }}>
                <div>
                  <label style={{ ...labelStyle, marginBottom: 2 }}>Generar PDF Automático</label>
                  <span style={{ fontSize: 11, color: '#475569' }}>Compila el reporte ejecutivo PDF profesional al completarse el escaneo.</span>
                </div>
                <div 
                  onClick={() => setAutoGeneratePdf(!autoGeneratePdf)}
                  style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                >
                  {autoGeneratePdf ? <ToggleRight size={28} color="#818cf8" /> : <ToggleLeft size={28} color="#475569" />}
                </div>
              </div>

            </div>
          </div>
        )}

        {/* STEP 4: CONFIRMACIÓN */}
        {step === 4 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            <h3 style={{ fontSize: 14, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '0.12em', color: '#818cf8', margin: 0 }}>
              Paso 4: Confirmar Auditoría
            </h3>
            
            <div style={{ background: 'rgba(2, 8, 23, 0.6)', border: '1px solid #1e293b', borderRadius: 16, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Título del Proyecto</span>
                  <span style={{ fontWeight: 600, color: '#e2e8f0', fontSize: 14, display: 'block', marginTop: 4 }}>{title}</span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Objetivo (Target)</span>
                  <span style={{ fontFamily: 'monospace', fontWeight: 600, color: '#818cf8', fontSize: 14, display: 'block', marginTop: 4 }}>{target}</span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Tipo Objetivo</span>
                  <span style={{ textTransform: 'capitalize', fontWeight: 600, color: '#e2e8f0', fontSize: 14, display: 'block', marginTop: 4 }}>{targetType}</span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Perfil Seleccionado</span>
                  <span style={{ textTransform: 'capitalize', fontWeight: 600, color: '#e2e8f0', fontSize: 14, display: 'block', marginTop: 4 }}>{profile}</span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Intensidad</span>
                  <span style={{ textTransform: 'capitalize', fontWeight: 600, color: '#e2e8f0', fontSize: 14, display: 'block', marginTop: 4 }}>{intensity}</span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: 10, color: '#64748b', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Rango Puertos</span>
                  <span style={{ fontFamily: 'monospace', fontWeight: 600, color: '#e2e8f0', fontSize: 14, display: 'block', marginTop: 4 }}>{portRange}</span>
                </div>
              </div>

              {/* Warning warning message */}
              <div style={{ background: 'rgba(239, 68, 68, 0.04)', border: '1px solid rgba(239, 68, 68, 0.15)', borderRadius: 12, padding: 16, display: 'flex', alignItems: 'start', gap: 12 }}>
                <ShieldAlert size={18} color="#fca5a5" style={{ flexShrink: 0, marginTop: 2 }} />
                <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>
                  <span style={{ fontWeight: 800, color: '#fca5a5', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: 2 }}>Autorización Legal</span>
                  Al hacer click en lanzar, declaras contar con la autorización explícita para auditar la IP o dominio especificado. Escaneos no autorizados pueden violar leyes locales.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* NAVIGATION BUTTONS */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 24, marginTop: 24 }}>
          <button
            onClick={handlePrevStep}
            disabled={step === 1}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '10px 18px',
              borderRadius: 12,
              background: 'transparent',
              border: '1px solid #1e293b',
              color: '#94a3b8',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
              opacity: step === 1 ? 0 : 1,
              pointerEvents: step === 1 ? 'none' : 'auto',
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255, 255, 255, 0.02)'; e.currentTarget.style.color = 'white'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#94a3b8'; }}
          >
            <ArrowLeft size={14} />
            Atrás
          </button>

          {step < 4 ? (
            <button
              onClick={handleNextStep}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '10px 20px',
                borderRadius: 12,
                background: 'linear-gradient(135deg, #4f46e5, #6366f1)',
                border: 'none',
                color: 'white',
                fontSize: 13,
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 4px 16px rgba(79, 70, 229, 0.3)',
                transition: 'all 0.2s',
              }}
              onMouseEnter={e => e.currentTarget.style.boxShadow = '0 8px 24px rgba(79, 70, 229, 0.45)'}
              onMouseLeave={e => e.currentTarget.style.boxShadow = '0 4px 16px rgba(79, 70, 229, 0.3)'}
            >
              <span>Continuar</span>
              <ArrowRight size={14} />
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '12px 24px',
                borderRadius: 12,
                background: 'linear-gradient(135deg, #10b981, #059669)',
                border: 'none',
                color: 'white',
                fontSize: 13,
                fontWeight: 700,
                cursor: 'pointer',
                boxShadow: '0 4px 16px rgba(16, 185, 129, 0.3)',
                transition: 'all 0.2s',
              }}
              onMouseEnter={e => e.currentTarget.style.boxShadow = '0 8px 24px rgba(16, 185, 129, 0.45)'}
              onMouseLeave={e => e.currentTarget.style.boxShadow = '0 4px 16px rgba(16, 185, 129, 0.3)'}
            >
              <Rocket size={16} />
              <span>Lanzar Auditoría</span>
            </button>
          )}
        </div>

      </div>

    </div>
  );
}
