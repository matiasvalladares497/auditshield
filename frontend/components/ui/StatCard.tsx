'use client';

import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ComponentType<{ size?: number; color?: string }>;
  variant?: 'brand' | 'success' | 'warning' | 'danger' | 'info';
  trend?: {
    value: string;
    isPositive: boolean;
  };
  className?: string;
}

const VARIANT_CONFIG = {
  brand: {
    accent: '#6366F1',
    accentFaint: 'rgba(99,102,241,0.08)',
    accentBorder: 'rgba(99,102,241,0.2)',
    accentGlow: 'rgba(99,102,241,0.12)',
    iconBg: 'rgba(99,102,241,0.15)',
    iconBorder: 'rgba(99,102,241,0.25)',
    valueColor: '#C7D2FE',
  },
  success: {
    accent: '#10B981',
    accentFaint: 'rgba(16,185,129,0.06)',
    accentBorder: 'rgba(16,185,129,0.2)',
    accentGlow: 'rgba(16,185,129,0.1)',
    iconBg: 'rgba(16,185,129,0.15)',
    iconBorder: 'rgba(16,185,129,0.25)',
    valueColor: '#6EE7B7',
  },
  warning: {
    accent: '#F59E0B',
    accentFaint: 'rgba(245,158,11,0.06)',
    accentBorder: 'rgba(245,158,11,0.2)',
    accentGlow: 'rgba(245,158,11,0.1)',
    iconBg: 'rgba(245,158,11,0.15)',
    iconBorder: 'rgba(245,158,11,0.25)',
    valueColor: '#FCD34D',
  },
  danger: {
    accent: '#EF4444',
    accentFaint: 'rgba(239,68,68,0.06)',
    accentBorder: 'rgba(239,68,68,0.2)',
    accentGlow: 'rgba(239,68,68,0.1)',
    iconBg: 'rgba(239,68,68,0.15)',
    iconBorder: 'rgba(239,68,68,0.25)',
    valueColor: '#FCA5A5',
  },
  info: {
    accent: '#3B82F6',
    accentFaint: 'rgba(59,130,246,0.06)',
    accentBorder: 'rgba(59,130,246,0.2)',
    accentGlow: 'rgba(59,130,246,0.1)',
    iconBg: 'rgba(59,130,246,0.15)',
    iconBorder: 'rgba(59,130,246,0.25)',
    valueColor: '#93C5FD',
  },
};

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'brand',
  trend,
  className,
}: StatCardProps) {
  const cfg = VARIANT_CONFIG[variant];

  return (
    <div
      style={{
        background: `linear-gradient(145deg, #0d1424, #0a101e)`,
        border: `1px solid ${cfg.accentBorder}`,
        borderRadius: 16,
        padding: '22px 24px',
        position: 'relative',
        overflow: 'hidden',
        transition: 'transform 0.2s, box-shadow 0.2s',
        boxShadow: `0 4px 24px ${cfg.accentGlow}, 0 1px 3px rgba(0,0,0,0.4)`,
        cursor: 'default',
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLElement).style.transform = 'translateY(-2px)';
        (e.currentTarget as HTMLElement).style.boxShadow = `0 8px 32px ${cfg.accentGlow}, 0 2px 8px rgba(0,0,0,0.5)`;
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLElement).style.transform = 'translateY(0)';
        (e.currentTarget as HTMLElement).style.boxShadow = `0 4px 24px ${cfg.accentGlow}, 0 1px 3px rgba(0,0,0,0.4)`;
      }}
    >
      {/* Ambient glow background */}
      <div style={{
        position: 'absolute',
        top: -30,
        right: -30,
        width: 100,
        height: 100,
        borderRadius: '50%',
        background: cfg.accentFaint,
        filter: 'blur(20px)',
        pointerEvents: 'none',
      }} />

      {/* Top row: title + icon */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <p style={{
          fontSize: 11,
          fontWeight: 700,
          color: '#64748B',
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          margin: 0,
        }}>
          {title}
        </p>
        <div style={{
          width: 38,
          height: 38,
          borderRadius: 10,
          background: cfg.iconBg,
          border: `1px solid ${cfg.iconBorder}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}>
          <Icon size={18} color={cfg.accent} />
        </div>
      </div>

      {/* Value */}
      <div style={{
        fontSize: 32,
        fontWeight: 800,
        color: cfg.valueColor,
        letterSpacing: '-1px',
        lineHeight: 1,
        marginBottom: 10,
      }}>
        {value}
      </div>

      {/* Bottom: trend + subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {trend && (
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 3,
            padding: '2px 8px',
            borderRadius: 9999,
            fontSize: 10,
            fontWeight: 700,
            background: trend.isPositive ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.12)',
            color: trend.isPositive ? '#34D399' : '#FCA5A5',
            border: trend.isPositive ? '1px solid rgba(16,185,129,0.2)' : '1px solid rgba(239,68,68,0.2)',
          }}>
            {trend.isPositive ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
            {trend.value}
          </span>
        )}
        {subtitle && (
          <span style={{ fontSize: 11, color: '#475569', fontWeight: 500 }}>
            {subtitle}
          </span>
        )}
      </div>

      {/* Bottom accent line */}
      <div style={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        height: 2,
        background: `linear-gradient(90deg, ${cfg.accent}40, ${cfg.accent}00)`,
        borderRadius: '0 0 16px 16px',
      }} />
    </div>
  );
}
