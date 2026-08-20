import type { Metadata } from 'next'
import './globals.css'
import { Toaster } from 'react-hot-toast'

export const metadata: Metadata = {
  title: 'AuditShield — Plataforma de Auditoría de Seguridad',
  description: 'Sistema profesional de auditoría de ciberseguridad. Escaneo completo de vulnerabilidades, análisis OWASP Top 10, SSL/TLS, DNS, puertos y generación de reportes ejecutivos PDF.',
  keywords: 'ciberseguridad, auditoría, vulnerabilidades, OWASP, penetration testing, seguridad web',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="es">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
      </head>
      <body>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#1E293B',
              color: '#F1F5F9',
              border: '1px solid #334155',
              borderRadius: '10px',
              fontSize: '14px',
            },
            success: {
              iconTheme: { primary: '#10B981', secondary: '#0F172A' },
            },
            error: {
              iconTheme: { primary: '#EF4444', secondary: '#0F172A' },
            },
          }}
        />
      </body>
    </html>
  )
}
