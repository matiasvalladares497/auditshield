'use client';

import { useState } from 'react';
import { useAuthStore } from '@/lib/store';
import {
  User, Lock, Bell, Shield, Eye, EyeOff, Save, CheckCircle2, Loader2, ToggleLeft, ToggleRight
} from 'lucide-react';
import toast from 'react-hot-toast';

type TabId = 'profile' | 'security' | 'notifications' | 'system';

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [activeTab, setActiveTab] = useState<TabId>('profile');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [saving, setSaving] = useState(false);

  // Profile form state
  const [profileForm, setProfileForm] = useState({
    full_name: user?.full_name || '',
    email: user?.email || '',
    username: user?.username || '',
    bio: '',
    organization: '',
  });

  // Security form
  const [securityForm, setSecurityForm] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });

  // Notification prefs
  const [notifPrefs, setNotifPrefs] = useState({
    audit_complete: true,
    critical_findings: true,
    report_ready: true,
    weekly_summary: false,
    email_notifications: true,
  });

  // System prefs
  const [systemPrefs, setSystemPrefs] = useState({
    auto_generate_pdf: true,
    default_scan_intensity: 'normal',
    default_port_range: '1-1000',
    scan_timeout: 300,
    max_concurrent_scans: 2,
    compliance_frameworks: ['owasp', 'nist'],
  });

  const handleSaveProfile = async () => {
    setSaving(true);
    await new Promise(r => setTimeout(r, 1000));
    setSaving(false);
    toast.success('Perfil actualizado correctamente');
  };

  const handleSavePassword = async () => {
    if (securityForm.new_password !== securityForm.confirm_password) {
      toast.error('Las contraseñas no coinciden');
      return;
    }
    if (securityForm.new_password.length < 8) {
      toast.error('La contraseña debe tener al menos 8 caracteres');
      return;
    }
    setSaving(true);
    await new Promise(r => setTimeout(r, 1000));
    setSaving(false);
    setSecurityForm({ current_password: '', new_password: '', confirm_password: '' });
    toast.success('Contraseña actualizada correctamente');
  };

  const handleSaveNotifications = async () => {
    setSaving(true);
    await new Promise(r => setTimeout(r, 800));
    setSaving(false);
    toast.success('Preferencias de notificaciones guardadas');
  };

  const handleSaveSystem = async () => {
    setSaving(true);
    await new Promise(r => setTimeout(r, 800));
    setSaving(false);
    toast.success('Configuración del sistema guardada');
  };

  // Shared Styles
  const glassCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.025)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(24px)',
    borderRadius: 16,
    padding: 28,
    boxShadow: '0 12px 32px rgba(0, 0, 0, 0.3)',
    display: 'flex',
    flexDirection: 'column',
    gap: 20,
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

  const buttonPrimaryStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '11px 22px',
    borderRadius: 12,
    background: 'linear-gradient(135deg, #4f46e5, #6366f1)',
    border: 'none',
    color: 'white',
    fontSize: 13,
    fontWeight: 700,
    cursor: 'pointer',
    boxShadow: '0 4px 16px rgba(79, 70, 229, 0.3)',
    transition: 'all 0.2s',
  };

  const tabsList = [
    { id: 'profile' as const, label: 'Perfil', icon: <User size={15} /> },
    { id: 'security' as const, label: 'Seguridad', icon: <Lock size={15} /> },
    { id: 'notifications' as const, label: 'Notificaciones', icon: <Bell size={15} /> },
    { id: 'system' as const, label: 'Sistema', icon: <Shield size={15} /> },
  ];

  return (
    <div style={{ maxWidth: 900, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 32 }}>
      {/* Header */}
      <div>
        <h1 style={{ fontSize: 24, fontWeight: 900, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
          Configuración
        </h1>
        <p style={{ fontSize: 13, color: '#64748B', marginTop: 4, margin: '4px 0 0' }}>
          Administra tu cuenta, seguridad y preferencias del sistema.
        </p>
      </div>

      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }} className="settings-container">
        
        {/* Sidebar tabs */}
        <nav style={{ width: 200, flexShrink: 0 }} className="settings-nav">
          <div style={{ background: 'rgba(255, 255, 255, 0.015)', border: '1px solid rgba(255, 255, 255, 0.06)', borderRadius: 16, overflow: 'hidden' }}>
            {tabsList.map((tab) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '14px 16px',
                    fontSize: 13,
                    fontWeight: isActive ? 700 : 500,
                    background: isActive ? 'rgba(99, 102, 241, 0.12)' : 'transparent',
                    border: 'none',
                    borderLeft: isActive ? '3px solid #818cf8' : '3px solid transparent',
                    color: isActive ? '#c7d2fe' : '#64748b',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    textAlign: 'left',
                  }}
                  onMouseEnter={e => {
                    if (!isActive) {
                      e.currentTarget.style.background = 'rgba(255,255,255,0.02)';
                      e.currentTarget.style.color = '#e2e8f0';
                    }
                  }}
                  onMouseLeave={e => {
                    if (!isActive) {
                      e.currentTarget.style.background = 'transparent';
                      e.currentTarget.style.color = '#64748b';
                    }
                  }}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Content Panel */}
        <div style={{ flex: 1, minWidth: 280 }}>

          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <div style={glassCardStyle}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 20, paddingBottom: 24, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{
                  width: 68,
                  height: 68,
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #4f46e5, #8b5cf6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 24,
                  fontWeight: 900,
                  color: 'white',
                  boxShadow: '0 0 20px rgba(99,102,241,0.3)',
                }}>
                  {(user?.full_name || user?.username || 'A')[0].toUpperCase()}
                </div>
                <div>
                  <h3 style={{ fontSize: 18, fontWeight: 800, color: '#f1f5f9', margin: 0 }}>
                    {user?.full_name || user?.username}
                  </h3>
                  <p style={{ fontSize: 13, color: '#64748b', margin: '4px 0 0' }}>{user?.email}</p>
                  <span style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    padding: '2px 8px',
                    borderRadius: 6,
                    background: 'rgba(99,102,241,0.08)',
                    border: '1px solid rgba(99,102,241,0.2)',
                    color: '#818cf8',
                    fontSize: 11,
                    fontWeight: 600,
                    marginTop: 6,
                  }}>
                    <Shield size={10} />
                    {user?.role || 'Analista'}
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <label style={labelStyle}>Nombre completo</label>
                    <input
                      type="text"
                      value={profileForm.full_name}
                      onChange={e => setProfileForm({ ...profileForm, full_name: e.target.value })}
                      style={inputStyle}
                    />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <label style={labelStyle}>Usuario</label>
                    <input
                      type="text"
                      value={profileForm.username}
                      onChange={e => setProfileForm({ ...profileForm, username: e.target.value })}
                      style={inputStyle}
                    />
                  </div>
                </div>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={labelStyle}>Correo electrónico</label>
                  <input
                    type="email"
                    value={profileForm.email}
                    onChange={e => setProfileForm({ ...profileForm, email: e.target.value })}
                    style={inputStyle}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={labelStyle}>Organización</label>
                  <input
                    type="text"
                    value={profileForm.organization}
                    onChange={e => setProfileForm({ ...profileForm, organization: e.target.value })}
                    placeholder="Nombre de tu organización..."
                    style={inputStyle}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={labelStyle}>Biografía</label>
                  <textarea
                    value={profileForm.bio}
                    onChange={e => setProfileForm({ ...profileForm, bio: e.target.value })}
                    rows={3}
                    placeholder="Cuéntanos sobre tu rol en seguridad..."
                    style={{ ...inputStyle, resize: 'none' }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'end', marginTop: 12 }}>
                <button
                  onClick={handleSaveProfile}
                  disabled={saving}
                  style={buttonPrimaryStyle}
                >
                  {saving ? (
                    <Loader2 size={14} className="animate-spin" />
                  ) : (
                    <Save size={14} />
                  )}
                  Guardar cambios
                </button>
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              
              <div style={glassCardStyle}>
                <h3 style={{ fontSize: 16, fontWeight: 800, color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
                  <Lock size={16} color="#818cf8" />
                  Cambiar contraseña
                </h3>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <label style={labelStyle}>Contraseña actual</label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showCurrentPassword ? 'text' : 'password'}
                        value={securityForm.current_password}
                        onChange={e => setSecurityForm({ ...securityForm, current_password: e.target.value })}
                        style={{ ...inputStyle, paddingRight: 40 }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                        style={{ position: 'absolute', right: 14, top: '55%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', display: 'flex', padding: 0 }}
                      >
                        {showCurrentPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <label style={labelStyle}>Nueva contraseña</label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={securityForm.new_password}
                        onChange={e => setSecurityForm({ ...securityForm, new_password: e.target.value })}
                        style={{ ...inputStyle, paddingRight: 40 }}
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        style={{ position: 'absolute', right: 14, top: '55%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#475569', display: 'flex', padding: 0 }}
                      >
                        {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    {securityForm.new_password && (
                      <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                        {[1, 2, 3, 4].map(i => (
                          <div
                            key={i}
                            style={{
                              height: 4,
                              flex: 1,
                              borderRadius: 2,
                              background: securityForm.new_password.length >= i * 3
                                ? i <= 1 ? '#ef4444' : i <= 2 ? '#f97316' : i <= 3 ? '#eab308' : '#10b981'
                                : 'rgba(255,255,255,0.06)',
                              transition: 'background 0.3s',
                            }}
                          />
                        ))}
                      </div>
                    )}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    <label style={labelStyle}>Confirmar contraseña</label>
                    <input
                      type="password"
                      value={securityForm.confirm_password}
                      onChange={e => setSecurityForm({ ...securityForm, confirm_password: e.target.value })}
                      style={inputStyle}
                    />
                    {securityForm.confirm_password && securityForm.new_password === securityForm.confirm_password && (
                      <p style={{ fontSize: 11, color: '#10b981', display: 'flex', alignItems: 'center', gap: 4, margin: '4px 0 0' }}><CheckCircle2 size={12} /> Las contraseñas coinciden</p>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'end', marginTop: 12 }}>
                  <button
                    onClick={handleSavePassword}
                    disabled={saving || !securityForm.current_password || !securityForm.new_password}
                    style={{ ...buttonPrimaryStyle, opacity: (saving || !securityForm.current_password || !securityForm.new_password) ? 0.5 : 1 }}
                  >
                    {saving ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
                    Cambiar contraseña
                  </button>
                </div>
              </div>

              {/* 2FA Section */}
              <div style={{ ...glassCardStyle, padding: 20 }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <h3 style={{ fontSize: 15, fontWeight: 800, color: '#f1f5f9', margin: 0 }}>Autenticación de doble factor (2FA)</h3>
                    <p style={{ fontSize: 12, color: '#64748b', margin: '4px 0 0' }}>Agrega una capa extra de seguridad a tu cuenta</p>
                  </div>
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 6, background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.2)', color: '#fbbf24' }}>
                    Próximamente
                  </span>
                </div>
              </div>

              {/* Sessions */}
              <div style={glassCardStyle}>
                <h3 style={{ fontSize: 15, fontWeight: 800, color: '#f1f5f9', margin: '0 0 4px' }}>Sesiones activas</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {[
                    { device: 'Chrome en Windows 11', ip: '192.168.1.100', time: 'Ahora mismo', current: true },
                    { device: 'Firefox en MacOS', ip: '192.168.1.105', time: 'Hace 2 días', current: false },
                  ].map((session, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(2,8,23,0.4)', border: '1px solid rgba(255,255,255,0.03)', borderRadius: 12, padding: 12 }}>
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', margin: 0 }}>{session.device}</p>
                        <p style={{ fontSize: 11, color: '#64748b', margin: '2px 0 0' }}>{session.ip} · {session.time}</p>
                      </div>
                      {session.current ? (
                        <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 9999, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', color: '#34d399' }}>Actual</span>
                      ) : (
                        <button style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#f87171', fontSize: 11, fontWeight: 600 }}>Cerrar</button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

            </div>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <div style={glassCardStyle}>
              <h3 style={{ fontSize: 16, fontWeight: 800, color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
                <Bell size={16} color="#818cf8" />
                Preferencias de notificaciones
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {[
                  { key: 'audit_complete', label: 'Auditoría completada', desc: 'Recibe una notificación cuando una auditoría finalice' },
                  { key: 'critical_findings', label: 'Hallazgos críticos', desc: 'Alerta inmediata cuando se detecte una vulnerabilidad crítica' },
                  { key: 'report_ready', label: 'Reporte listo', desc: 'Notificar cuando un PDF esté generado y listo para descargar' },
                  { key: 'weekly_summary', label: 'Resumen semanal', desc: 'Resumen de actividad de auditorías cada semana' },
                  { key: 'email_notifications', label: 'Notificaciones por email', desc: 'Enviar notificaciones al correo registrado' },
                ].map((item) => {
                  const val = notifPrefs[item.key as keyof typeof notifPrefs];
                  return (
                    <div key={item.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 14, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', margin: 0 }}>{item.label}</p>
                        <p style={{ fontSize: 11, color: '#64748b', margin: '2px 0 0' }}>{item.desc}</p>
                      </div>
                      <div 
                        onClick={() => setNotifPrefs(prev => ({ ...prev, [item.key]: !val }))}
                        style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                      >
                        {val ? <ToggleRight size={28} color="#818cf8" /> : <ToggleLeft size={28} color="#475569" />}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div style={{ display: 'flex', justifyContent: 'end', marginTop: 12 }}>
                <button
                  onClick={handleSaveNotifications}
                  disabled={saving}
                  style={buttonPrimaryStyle}
                >
                  {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                  Guardar preferencias
                </button>
              </div>
            </div>
          )}

          {/* System Tab */}
          {activeTab === 'system' && (
            <div style={glassCardStyle}>
              <h3 style={{ fontSize: 16, fontWeight: 800, color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
                <Shield size={16} color="#818cf8" />
                Configuración del sistema
              </h3>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={labelStyle}>Intensidad de escaneo por defecto</label>
                  <select
                    value={systemPrefs.default_scan_intensity}
                    onChange={e => setSystemPrefs({ ...systemPrefs, default_scan_intensity: e.target.value })}
                    style={inputStyle}
                  >
                    <option value="stealth" style={{ background: '#020817' }}>Silencioso (Stealth) — Menos detectable</option>
                    <option value="normal" style={{ background: '#020817' }}>Normal — Equilibrado</option>
                    <option value="aggressive" style={{ background: '#020817' }}>Agresivo — Más completo pero más ruidoso</option>
                  </select>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <label style={labelStyle}>Rango de puertos por defecto</label>
                  <input
                    type="text"
                    value={systemPrefs.default_port_range}
                    onChange={e => setSystemPrefs({ ...systemPrefs, default_port_range: e.target.value })}
                    placeholder="ej: 1-1000, 80,443,8080"
                    style={inputStyle}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <label style={{ ...labelStyle, display: 'flex', justifyContent: 'space-between' }}>
                    <span>Timeout de escaneo (segundos)</span>
                    <span style={{ color: '#818cf8' }}>{systemPrefs.scan_timeout}s</span>
                  </label>
                  <input
                    type="range"
                    min={60}
                    max={900}
                    step={30}
                    value={systemPrefs.scan_timeout}
                    onChange={e => setSystemPrefs({ ...systemPrefs, scan_timeout: parseInt(e.target.value) })}
                    style={{ width: '100%', accentColor: '#818cf8' }}
                  />
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#475569' }}>
                    <span>1 min</span>
                    <span>15 min</span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 14, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <div>
                    <p style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', margin: 0 }}>Generar PDF automáticamente</p>
                    <p style={{ fontSize: 11, color: '#64748b', margin: '2px 0 0' }}>Crear reporte PDF al finalizar cada auditoría</p>
                  </div>
                  <div 
                    onClick={() => setSystemPrefs(prev => ({ ...prev, auto_generate_pdf: !prev.auto_generate_pdf }))}
                    style={{ cursor: 'pointer', display: 'flex', alignItems: 'center' }}
                  >
                    {systemPrefs.auto_generate_pdf ? <ToggleRight size={28} color="#818cf8" /> : <ToggleLeft size={28} color="#475569" />}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <label style={labelStyle}>Frameworks de cumplimiento</label>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    {['owasp', 'nist', 'iso27001', 'pci_dss', 'cis'].map(fw => {
                      const isSelected = systemPrefs.compliance_frameworks.includes(fw);
                      return (
                        <button
                          key={fw}
                          onClick={() => {
                            const updated = systemPrefs.compliance_frameworks.includes(fw)
                              ? systemPrefs.compliance_frameworks.filter(f => f !== fw)
                              : [...systemPrefs.compliance_frameworks, fw];
                            setSystemPrefs({ ...systemPrefs, compliance_frameworks: updated });
                          }}
                          style={{
                            padding: '6px 12px',
                            borderRadius: 8,
                            fontSize: 12,
                            fontWeight: 600,
                            background: isSelected ? 'rgba(99,102,241,0.08)' : 'transparent',
                            border: isSelected ? '1px solid rgba(99,102,241,0.25)' : '1px solid #1e293b',
                            color: isSelected ? '#818cf8' : '#64748b',
                            cursor: 'pointer',
                            transition: 'all 0.2s',
                          }}
                          onMouseEnter={e => {
                            if (!isSelected) {
                              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)';
                              e.currentTarget.style.color = '#e2e8f0';
                            }
                          }}
                          onMouseLeave={e => {
                            if (!isSelected) {
                              e.currentTarget.style.borderColor = '#1e293b';
                              e.currentTarget.style.color = '#64748b';
                            }
                          }}
                        >
                          {fw.toUpperCase().replace('_', ' ')}
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'end', marginTop: 12 }}>
                <button
                  onClick={handleSaveSystem}
                  disabled={saving}
                  style={buttonPrimaryStyle}
                >
                  {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                  Guardar configuración
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @media (max-width: 768px) {
          .settings-container { flex-direction: column !important; }
          .settings-nav { width: 100% !important; }
        }
      `}</style>
    </div>
  );
}
