'use client';

import Link from 'next/link';
import { Shield, Home, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-[var(--bg-base)] flex items-center justify-center relative overflow-hidden">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage: `
            linear-gradient(rgba(99,102,241,0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(99,102,241,0.3) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
        }}
      />

      {/* Glow effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[var(--brand-primary)]/10 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-700/10 rounded-full blur-3xl" />

      <div className="relative z-10 text-center space-y-8">
        {/* Logo */}
        <div className="flex items-center justify-center gap-3 mb-8">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[var(--brand-primary)] to-purple-700 flex items-center justify-center">
            <Shield size={24} className="text-white" />
          </div>
          <span className="text-2xl font-bold text-[var(--text-primary)]">AuditShield</span>
        </div>

        {/* 404 */}
        <div>
          <h1 className="text-9xl font-black bg-gradient-to-br from-[var(--brand-primary)] to-purple-400 bg-clip-text text-transparent leading-none">
            404
          </h1>
          <div className="mt-4 text-xl font-semibold text-[var(--text-primary)]">Página no encontrada</div>
          <p className="mt-2 text-[var(--text-secondary)] max-w-md">
            La ruta que buscas no existe o fue movida. Verifica la URL o regresa al dashboard.
          </p>
        </div>

        {/* Terminal-style message */}
        <div className="bg-[var(--bg-surface)] border border-white/10 rounded-xl p-4 font-mono text-sm text-left max-w-sm mx-auto">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <div className="space-y-1">
            <p className="text-green-400">$ audit-shield --locate <span className="text-white">página</span></p>
            <p className="text-red-400">ERROR: Ruta no encontrada (404)</p>
            <p className="text-[var(--text-secondary)]">$ Sugerencia: navegar a /dashboard</p>
            <p className="text-[var(--brand-secondary)] animate-pulse">▋</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-center gap-4">
          <Link
            href="/dashboard"
            className="flex items-center gap-2 bg-[var(--brand-primary)] hover:bg-[var(--brand-secondary)] text-white px-6 py-3 rounded-xl font-medium transition-all hover:shadow-lg hover:shadow-[var(--brand-primary)]/25"
          >
            <Home size={18} />
            Ir al Dashboard
          </Link>
          <button
            onClick={() => window.history.back()}
            className="flex items-center gap-2 bg-white/5 hover:bg-white/10 border border-white/10 text-[var(--text-primary)] px-6 py-3 rounded-xl font-medium transition-all"
          >
            <ArrowLeft size={18} />
            Volver atrás
          </button>
        </div>
      </div>
    </div>
  );
}
