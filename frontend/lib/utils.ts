import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

// ─── Class Merger ─────────────────────────────────────────────────────────────

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// ─── Date Formatting ──────────────────────────────────────────────────────────

export function formatDate(date: string | Date | null | undefined): string {
  if (!date) return '—';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return '—';
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  return `${day}/${month}/${year} ${hours}:${minutes}`;
}

// ─── Duration Formatting ──────────────────────────────────────────────────────

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${secs}s`;
  const hrs = Math.floor(mins / 60);
  const remainMins = mins % 60;
  return `${hrs}h ${remainMins}m`;
}

// ─── Severity Color ───────────────────────────────────────────────────────────

export function getSeverityColor(
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string
): string {
  const map: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };
  return map[severity?.toLowerCase()] ?? 'badge-info';
}

export function getSeverityHex(severity: string): string {
  const map: Record<string, string> = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#2563EB',
    info: '#6B7280',
  };
  return map[severity?.toLowerCase()] ?? '#6B7280';
}

// ─── Score Utilities ──────────────────────────────────────────────────────────

export function getScoreColor(score: number | null | undefined): string {
  if (score == null) return '#6B7280';
  if (score >= 90) return '#10B981';
  if (score >= 75) return '#34D399';
  if (score >= 60) return '#F59E0B';
  if (score >= 45) return '#FB923C';
  if (score >= 30) return '#F97316';
  return '#EF4444';
}

export function getScoreLetter(score: number | null | undefined): string {
  if (score == null) return '?';
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 45) return 'D';
  return 'F';
}

export function getScoreClass(score: number | null | undefined): string {
  if (score == null) return '';
  if (score >= 95) return 'score-a-plus';
  if (score >= 85) return 'score-a';
  if (score >= 75) return 'score-b';
  if (score >= 60) return 'score-c';
  if (score >= 45) return 'score-d';
  return 'score-f';
}

// ─── Status Utilities ─────────────────────────────────────────────────────────

export function getStatusIcon(status: string): string {
  const map: Record<string, string> = {
    pending: '⏳',
    running: '🔄',
    completed: '✅',
    failed: '❌',
    cancelled: '🚫',
  };
  return map[status] ?? '❓';
}

export function getStatusLabel(status: string): string {
  const map: Record<string, string> = {
    pending: 'Pendiente',
    running: 'En progreso',
    completed: 'Completado',
    failed: 'Fallido',
    cancelled: 'Cancelado',
  };
  return map[status] ?? status;
}

export function getStatusBadgeClass(status: string): string {
  const map: Record<string, string> = {
    running: 'badge-low',
    completed: '',
    failed: 'badge-critical',
    cancelled: 'badge-info',
    pending: 'badge-info',
  };
  return map[status] ?? 'badge-info';
}

// ─── String Utilities ─────────────────────────────────────────────────────────

export function truncate(str: string, maxLen: number): string {
  if (!str) return '';
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

export function getInitials(name: string): string {
  if (!name) return '?';
  const parts = name.trim().split(' ');
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function capitalize(str: string): string {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}
