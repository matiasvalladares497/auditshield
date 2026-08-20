'use client';

import React, { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { 
  Server, 
  Plus, 
  Trash2, 
  ScanLine, 
  Tag,
  X,
  Loader2
} from 'lucide-react';
import { assetsApi, type Asset } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import toast from 'react-hot-toast';

export default function AssetsPage() {
  const router = useRouter();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Form Fields
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [assetType, setAssetType] = useState('domain');
  const [description, setDescription] = useState('');
  const [tagInput, setTagInput] = useState('');
  const [tags, setTags] = useState<string[]>([]);

  const fetchAssets = async () => {
    setLoading(true);
    try {
      const data = await assetsApi.list();
      setAssets(data);
    } catch (error) {
      toast.error('Error al cargar inventario de activos.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleAddTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      setTags([...tags, tagInput.trim()]);
      setTagInput('');
    }
  };

  const handleRemoveTag = (t: string) => {
    setTags(tags.filter(tag => tag !== t));
  };

  const handleSaveAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !target.trim()) {
      toast.error('Por favor completa los campos requeridos.');
      return;
    }

    setSubmitting(true);
    try {
      await assetsApi.create({
        name,
        target,
        asset_type: assetType,
        description,
        tags
      });
      toast.success('Activo registrado exitosamente.');
      setIsModalOpen(false);
      
      // Reset form
      setName('');
      setTarget('');
      setDescription('');
      setTags([]);
      
      fetchAssets();
    } catch (error) {
      toast.error('Error al registrar el activo.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteAsset = async (id: number) => {
    if (!confirm('¿Seguro que deseas eliminar este activo del inventario?')) return;
    try {
      await assetsApi.delete(id);
      toast.success('Activo eliminado del sistema.');
      fetchAssets();
    } catch (error) {
      toast.error('Error al eliminar el activo.');
    }
  };

  const handleAuditNow = (asset: Asset) => {
    router.push(`/dashboard/audits/new?asset_id=${asset.id}`);
  };

  // Shared Styles
  const glassCardStyle: React.CSSProperties = {
    background: 'rgba(255, 255, 255, 0.025)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    backdropFilter: 'blur(24px)',
    borderRadius: 16,
    padding: 24,
    boxShadow: '0 12px 32px rgba(0, 0, 0, 0.3)',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    transition: 'all 0.3s',
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      
      {/* Header and Add Button */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(99,102,241,0.1)', paddingBottom: 24, gap: 16 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 900, color: '#F1F5F9', letterSpacing: '-0.5px', margin: 0 }}>
            Inventario de Activos
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4, margin: '4px 0 0' }}>
            Gestiona y monitorea los servidores, redes y sitios web bajo tu responsabilidad.
          </p>
        </div>
        
        <button
          onClick={() => setIsModalOpen(true)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '10px 18px',
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
          <Plus size={16} />
          <span>Registrar Activo</span>
        </button>
      </div>

      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 300, flexDirection: 'column', gap: 12 }}>
          <Loader2 size={32} className="animate-spin" color="#6366f1" />
          <span style={{ fontSize: 14, color: '#64748b', fontWeight: 500 }}>Cargando inventario...</span>
        </div>
      ) : assets.length === 0 ? (
        <div style={{
          background: 'rgba(255,255,255,0.01)',
          border: '1px dashed #1e293b',
          borderRadius: 20,
          padding: 48,
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 16,
        }}>
          <Server size={48} color="#334155" />
          <div>
            <p style={{ fontSize: 16, fontWeight: 700, color: '#94a3b8', margin: 0 }}>Sin activos registrados</p>
            <p style={{ fontSize: 13, color: '#475569', marginTop: 4, margin: '4px 0 0' }}>Registra tus servidores, webs o IPs para realizar auditorías rápidas.</p>
          </div>
          <button
            onClick={() => setIsModalOpen(true)}
            style={{
              padding: '10px 18px',
              borderRadius: 12,
              background: 'rgba(99,102,241,0.1)',
              border: '1px solid rgba(99,102,241,0.25)',
              color: '#818cf8',
              fontSize: 13,
              fontWeight: 700,
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            Registrar Primer Activo
          </button>
        </div>
      ) : (
        /* Grid of Assets */
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 20 }}>
          {assets.map((asset) => {
            const lastScore = asset.last_score;
            
            return (
              <div 
                key={asset.id} 
                className="asset-card"
                style={glassCardStyle}
              >
                <div>
                  {/* Top: Name, Type and Delete */}
                  <div style={{ display: 'flex', alignItems: 'start', justifyContent: 'space-between', gap: 8 }}>
                    <div>
                      <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: '#4f46e5', letterSpacing: '0.08em', fontFamily: 'monospace' }}>
                        {asset.asset_type}
                      </span>
                      <h4 style={{ fontSize: 16, fontWeight: 800, color: '#f1f5f9', margin: '4px 0 0' }}>{asset.name}</h4>
                    </div>
                    <button
                      onClick={() => handleDeleteAsset(asset.id)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        cursor: 'pointer',
                        color: '#475569',
                        padding: 4,
                        borderRadius: 6,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        transition: 'all 0.2s',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.color = '#ef4444'; e.currentTarget.style.background = 'rgba(239,68,68,0.1)'; }}
                      onMouseLeave={e => { e.currentTarget.style.color = '#475569'; e.currentTarget.style.background = 'transparent'; }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>

                  {/* Target string block */}
                  <p style={{
                    fontSize: 12,
                    fontFamily: 'monospace',
                    color: '#818cf8',
                    background: 'rgba(0, 0, 0, 0.25)',
                    border: '1px solid rgba(255,255,255,0.03)',
                    padding: 10,
                    borderRadius: 8,
                    margin: '16px 0',
                    wordBreak: 'break-all',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}>
                    {asset.target}
                  </p>

                  {/* Description */}
                  {asset.description && (
                    <p style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5, margin: '0 0 16px' }}>
                      {asset.description}
                    </p>
                  )}

                  {/* Tags list */}
                  {asset.tags && asset.tags.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
                      {asset.tags.map((tag, idx) => (
                        <span key={idx} style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          fontSize: 10,
                          fontWeight: 700,
                          background: 'rgba(255,255,255,0.03)',
                          color: '#94a3b8',
                          padding: '3px 8px',
                          borderRadius: 9999,
                          border: '1px solid rgba(255,255,255,0.05)',
                        }}>
                          <Tag size={10} />
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Score and actions row */}
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 16, marginTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    {lastScore != null ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span 
                          style={{
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            background: lastScore >= 75 ? '#10B981' : lastScore >= 60 ? '#F59E0B' : '#EF4444',
                            boxShadow: `0 0 8px ${lastScore >= 75 ? '#10B981' : lastScore >= 60 ? '#F59E0B' : '#EF4444'}`,
                          }}
                        />
                        <span style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>
                          Score: {Math.round(lastScore)}%
                        </span>
                      </div>
                    ) : (
                      <span style={{ fontSize: 12, color: '#475569' }}>Sin auditar</span>
                    )}
                    <span style={{ display: 'block', fontSize: 10, color: '#475569', marginTop: 4 }}>
                      {asset.last_audited ? `Auditoría: ${formatDate(asset.last_audited)}` : 'Nunca'}
                    </span>
                  </div>
                  
                  <button
                    onClick={() => handleAuditNow(asset)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '6px 12px',
                      borderRadius: 8,
                      background: 'rgba(99,102,241,0.08)',
                      border: '1px solid rgba(99,102,241,0.25)',
                      color: '#818cf8',
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(99,102,241,0.18)'; e.currentTarget.style.borderColor = 'rgba(99,102,241,0.4)'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'rgba(99,102,241,0.08)'; e.currentTarget.style.borderColor = 'rgba(99,102,241,0.25)'; }}
                  >
                    <ScanLine size={13} />
                    <span>Auditar</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* CREATE MODAL */}
      {isModalOpen && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.6)',
          backdropFilter: 'blur(8px)',
          zIndex: 50,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 16,
        }}>
          <div style={{
            ...glassCardStyle,
            width: '100%',
            maxWidth: 440,
            padding: 0,
            overflow: 'hidden',
          }}>
            {/* Modal header */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '16px 24px',
              background: 'rgba(255,255,255,0.02)',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
            }}>
              <h3 style={{ fontSize:15, fontWeight:800, color:'#f1f5f9', display:'flex', alignItems:'center', gap:8, margin:0 }}>
                <Server size={18} color="#818cf8" />
                <span>Registrar Activo</span>
              </h3>
              <button 
                onClick={() => setIsModalOpen(false)}
                style={{ background:'none', border:'none', cursor:'pointer', color:'#475569', display:'flex', padding:0 }}
                onMouseEnter={e => e.currentTarget.style.color = '#f1f5f9'}
                onMouseLeave={e => e.currentTarget.style.color = '#475569'}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal form */}
            <form onSubmit={handleSaveAsset} style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
              
              {/* Nombre */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Nombre del Activo *</label>
                <input
                  type="text" required placeholder="Ej: Servidor Web Principal, BD Alumnos"
                  value={name} onChange={(e) => setName(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                />
              </div>

              {/* Target / Objetivo */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Objetivo (IP, Dominio, CIDR) *</label>
                <input
                  type="text" required placeholder="Ej: 192.168.10.2 o liceotecnico.cl"
                  value={target} onChange={(e) => setTarget(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                />
              </div>

              {/* Tipo Activo */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Tipo de Activo</label>
                <select
                  value={assetType} onChange={(e) => setAssetType(e.target.value)}
                  style={inputStyle}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                >
                  <option value="domain" style={{ background: '#020817' }}>Dominio / Subdominio</option>
                  <option value="ip" style={{ background: '#020817' }}>Dirección IP Estática</option>
                  <option value="url" style={{ background: '#020817' }}>URL Web Completa</option>
                  <option value="cidr" style={{ background: '#020817' }}>Rango de Red (CIDR)</option>
                </select>
              </div>

              {/* Descripción */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Descripción (Opcional)</label>
                <textarea
                  placeholder="Indique detalles del servidor, ubicación, etc..."
                  value={description} onChange={(e) => setDescription(e.target.value)} rows={2}
                  style={{ ...inputStyle, resize: 'none' }}
                  onFocus={e => e.target.style.borderColor = '#818cf8'}
                  onBlur={e => e.target.style.borderColor = '#1e293b'}
                />
              </div>

              {/* Tags input */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <label style={labelStyle}>Etiquetas (Tags)</label>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    type="text" placeholder="Ej: Produccion, DMZ"
                    value={tagInput} onChange={(e) => setTagInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddTag(); } }}
                    style={{ ...inputStyle, flex: 1 }}
                    onFocus={e => e.target.style.borderColor = '#818cf8'}
                    onBlur={e => e.target.style.borderColor = '#1e293b'}
                  />
                  <button
                    type="button" onClick={handleAddTag}
                    style={{
                      padding: '0 14px',
                      borderRadius: 12,
                      background: 'transparent',
                      border: '1px solid #1e293b',
                      color: '#94a3b8',
                      fontSize: 12,
                      fontWeight: 600,
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.02)'; e.currentTarget.style.color = '#f1f5f9'; }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = '#94a3b8'; }}
                  >
                    Añadir
                  </button>
                </div>
                {tags.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, paddingTop: 8 }}>
                    {tags.map((tag, idx) => (
                      <span key={idx} style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        fontSize: 10,
                        fontWeight: 700,
                        background: 'rgba(99,102,241,0.08)',
                        color: '#c7d2fe',
                        padding: '3px 8px',
                        borderRadius: 9999,
                        border: '1px solid rgba(99,102,241,0.25)',
                      }}>
                        <span>{tag}</span>
                        <button 
                          type="button" onClick={() => handleRemoveTag(tag)}
                          style={{ background:'none', border:'none', cursor:'pointer', color:'#475569', display:'flex', padding:0 }}
                          onMouseEnter={e => e.currentTarget.style.color = '#ef4444'}
                          onMouseLeave={e => e.currentTarget.style.color = '#475569'}
                        >
                          <X size={10} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'end', gap: 12, borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 12 }}>
                <button
                  type="button" onClick={() => setIsModalOpen(false)}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 10,
                    background: 'transparent',
                    border: '1px solid #1e293b',
                    color: '#64748b',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                  onMouseEnter={e => e.currentTarget.style.color = '#f1f5f9'}
                  onMouseLeave={e => e.currentTarget.style.color = '#64748b'}
                >
                  Cancelar
                </button>
                <button
                  type="submit" disabled={submitting}
                  style={{
                    padding: '8px 16px',
                    borderRadius: 10,
                    background: 'linear-gradient(135deg, #4f46e5, #6366f1)',
                    border: 'none',
                    color: 'white',
                    fontSize: 12,
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    boxShadow: '0 4px 16px rgba(79, 70, 229, 0.3)',
                  }}
                >
                  {submitting && <Loader2 size={12} className="animate-spin" />}
                  <span>Guardar Activo</span>
                </button>
              </div>

            </form>
          </div>
        </div>
      )}

      {/* CSS Hover Classes Fallback */}
      <style>{`
        .asset-card:hover {
          border-color: rgba(255, 255, 255, 0.15) !important;
          background: rgba(255, 255, 255, 0.04) !important;
          transform: translateY(-2px);
        }
      `}</style>
    </div>
  );
}
