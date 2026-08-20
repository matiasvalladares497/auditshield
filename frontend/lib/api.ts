import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as mockDb from './mockData';

// ─── Types ────────────────────────────────────────────────────────────────────

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface User {
  id: number;
  email: string;
  username: string;
  full_name: string;
  role: string;
  created_at: string;
}

export interface RegisterData {
  email: string;
  username: string;
  full_name: string;
  password: string;
}

export interface AuditSummary {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
  total?: number;
}

export interface Audit {
  id: number;
  title: string;
  target: string;
  target_type: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  profile: string;
  score: number | null;
  score_letter: string | null;
  security_score?: number | null; // support both database styles
  created_at: string;
  completed_at: string | null;
  duration: number | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  progress: number;
  current_module: string | null;
  notes: string | null;
  options: Record<string, unknown>;
  modules?: string[] | Record<string, boolean>;
  findings?: Finding[];
  summary?: AuditSummary;
}

export interface AuditCreateData {
  title: string;
  target: string;
  target_type: string;
  profile: string;
  modules: string[] | Record<string, boolean>;
  scan_options?: {
    intensity: string;
    port_range: string;
    auto_generate_pdf: boolean;
  };
  intensity?: string;
  port_range?: string;
  auto_report?: boolean;
  notes?: string;
  asset_id?: number | null;
}

export interface Finding {
  id: number;
  audit_id: number;
  finding_id: string | null;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  module: string;
  cvss_score: number | null;
  cvss_vector?: string | null;
  cve_id: string | null;
  evidence: string | null;
  impact: string | null;
  recommendation: string | null;
  references: string[];
  status: 'open' | 'false_positive' | 'remediated';
  is_remediated?: boolean;
  is_false_positive?: boolean;
  created_at: string;
}

export interface FindingFilters {
  severity?: string;
  module?: string;
  search?: string;
  status?: string;
}

export interface Asset {
  id: number;
  name: string;
  target: string;
  asset_type: string;
  last_score: number | null;
  last_score_letter: string | null;
  last_audit_at?: string | null;
  last_audited?: string | null;
  created_at: string;
  description?: string | null;
  tags?: string[];
}

export interface AssetCreateData {
  name: string;
  target: string;
  asset_type: string;
  description?: string;
  tags?: string[];
}

export interface Report {
  id: number;
  audit_id: number;
  audit_title: string;
  report_type: string;
  file_size: number | null;
  created_at: string;
  status: 'generating' | 'ready' | 'failed';
}

export interface ReportGenerateData {
  audit_id: number;
  report_type: string;
}

// ─── Axios Instance ───────────────────────────────────────────────────────────

const api: AxiosInstance = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Helper to check if we should run in demo fallback mode
const isDemoMode = () => {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem('auth_token') === 'demo-token-auditshield-2024';
};

// ─── Request Interceptor ──────────────────────────────────────────────────────

api.interceptors.request.use(
  (config) => {
    if (typeof window !== 'undefined') {
      if (!process.env.NEXT_PUBLIC_API_URL && window.location.hostname) {
        config.baseURL = `http://${window.location.hostname}:8000`;
      }
      const token = localStorage.getItem('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ─── Response Interceptor ─────────────────────────────────────────────────────

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
        // Avoid infinite redirect loops
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  }
);

// ─── Auth API ─────────────────────────────────────────────────────────────────

export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);
    const res: AxiosResponse<LoginResponse> = await api.post('/api/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    return res.data;
  },

  register: async (data: RegisterData): Promise<User> => {
    const res: AxiosResponse<User> = await api.post('/api/auth/register', data);
    return res.data;
  },

  me: async (): Promise<User> => {
    const res: AxiosResponse<User> = await api.get('/api/auth/me');
    return res.data;
  },
};

// ─── Audits API ───────────────────────────────────────────────────────────────

export const auditsApi = {
  list: async (): Promise<Audit[]> => {
    if (isDemoMode()) {
      return mockDb.getMockAudits() as unknown as Audit[];
    }
    try {
      const res: AxiosResponse<Audit[]> = await api.get('/api/audits');
      return res.data;
    } catch (err) {
      console.log('Fallando a base de datos de demo (Auditorías)');
      return mockDb.getMockAudits() as unknown as Audit[];
    }
  },

  get: async (id: number | string): Promise<Audit> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      const audit = mockDb.getMockAudit(numericId);
      if (!audit) throw new Error('Not found');
      const findings = mockDb.getMockFindings(numericId);
      return {
        ...audit,
        findings: findings as unknown as Finding[],
      } as unknown as Audit;
    }
    try {
      const res: AxiosResponse<Audit> = await api.get(`/api/audits/${id}`);
      return res.data;
    } catch (err) {
      console.log(`Fallando a base de datos de demo para auditoría ${id}`);
      const audit = mockDb.getMockAudit(numericId);
      if (!audit) throw err;
      const findings = mockDb.getMockFindings(numericId);
      return {
        ...audit,
        findings: findings as unknown as Finding[],
      } as unknown as Audit;
    }
  },

  create: async (data: AuditCreateData): Promise<Audit> => {
    if (isDemoMode()) {
      return mockDb.createMockAudit(data) as unknown as Audit;
    }
    try {
      const res: AxiosResponse<Audit> = await api.post('/api/audits', data);
      return res.data;
    } catch (err) {
      console.log('Creando auditoría en la base de datos de demo');
      return mockDb.createMockAudit(data) as unknown as Audit;
    }
  },

  delete: async (id: number | string): Promise<void> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      mockDb.deleteMockAudit(numericId);
      return;
    }
    try {
      await api.delete(`/api/audits/${id}`);
    } catch (err) {
      mockDb.deleteMockAudit(numericId);
    }
  },

  cancel: async (id: number | string): Promise<Audit> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      const audit = mockDb.getMockAudit(numericId);
      if (audit) {
        audit.status = 'cancelled';
        mockDb.updateMockAudit(audit);
        return audit as unknown as Audit;
      }
      throw new Error('Not found');
    }
    try {
      const res: AxiosResponse<Audit> = await api.post(`/api/audits/${id}/cancel`);
      return res.data;
    } catch (err) {
      const audit = mockDb.getMockAudit(numericId);
      if (audit) {
        audit.status = 'cancelled';
        mockDb.updateMockAudit(audit);
        return audit as unknown as Audit;
      }
      throw err;
    }
  },

  getFindings: async (
    id: number | string,
    filters?: FindingFilters
  ): Promise<Finding[]> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      return mockDb.getMockFindings(numericId) as unknown as Finding[];
    }
    try {
      const res: AxiosResponse<Finding[]> = await api.get(
        `/api/audits/${id}/findings`,
        { params: filters }
      );
      return res.data;
    } catch (err) {
      return mockDb.getMockFindings(numericId) as unknown as Finding[];
    }
  },

  // Added update finding for false positive/remediated toggle in demo mode
  updateFinding: async (
    auditId: number | string,
    findingId: number | string,
    data: { status: string; is_remediated?: boolean; is_false_positive?: boolean }
  ): Promise<Finding> => {
    const aId = typeof auditId === 'string' ? parseInt(auditId) : auditId;
    const fId = typeof findingId === 'string' ? parseInt(findingId) : findingId;
    
    if (isDemoMode()) {
      const res = mockDb.updateMockFinding(aId, fId, data as any);
      if (!res) throw new Error('Finding not found');
      return res as unknown as Finding;
    }
    try {
      const res: AxiosResponse<Finding> = await api.put(
        `/api/audits/${auditId}/findings/${findingId}`,
        data
      );
      return res.data;
    } catch (err) {
      const res = mockDb.updateMockFinding(aId, fId, data as any);
      if (!res) throw err;
      return res as unknown as Finding;
    }
  }
};

// ─── Assets API ───────────────────────────────────────────────────────────────

export const assetsApi = {
  list: async (): Promise<Asset[]> => {
    if (isDemoMode()) {
      return mockDb.getMockAssets() as unknown as Asset[];
    }
    try {
      const res: AxiosResponse<Asset[]> = await api.get('/api/assets');
      return res.data;
    } catch (err) {
      return mockDb.getMockAssets() as unknown as Asset[];
    }
  },

  create: async (data: AssetCreateData): Promise<Asset> => {
    if (isDemoMode()) {
      return mockDb.createMockAsset(data) as unknown as Asset;
    }
    try {
      const res: AxiosResponse<Asset> = await api.post('/api/assets', data);
      return res.data;
    } catch (err) {
      return mockDb.createMockAsset(data) as unknown as Asset;
    }
  },

  delete: async (id: number | string): Promise<void> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      mockDb.deleteMockAsset(numericId);
      return;
    }
    try {
      await api.delete(`/api/assets/${id}`);
    } catch (err) {
      mockDb.deleteMockAsset(numericId);
    }
  },
};

// ─── Reports API ──────────────────────────────────────────────────────────────

export const reportsApi = {
  generate: async (data: ReportGenerateData): Promise<Report> => {
    if (isDemoMode()) {
      return mockDb.createMockReport(data.audit_id, data.report_type) as unknown as Report;
    }
    try {
      const res: AxiosResponse<Report> = await api.post('/api/reports/generate', data);
      return res.data;
    } catch (err) {
      return mockDb.createMockReport(data.audit_id, data.report_type) as unknown as Report;
    }
  },

  list: async (): Promise<Report[]> => {
    if (isDemoMode()) {
      return mockDb.getMockReports() as unknown as Report[];
    }
    try {
      const res: AxiosResponse<Report[]> = await api.get('/api/reports');
      return res.data;
    } catch (err) {
      return mockDb.getMockReports() as unknown as Report[];
    }
  },

  download: async (id: number | string): Promise<Blob> => {
    if (isDemoMode()) {
      const reports = mockDb.getMockReports();
      const report = reports.find(r => r.id === Number(id));
      if (!report) throw new Error("Report not found");
      
      const audit = mockDb.getMockAudit(report.audit_id);
      if (!audit) throw new Error("Audit not found");
      
      const findings = mockDb.getMockFindings(report.audit_id);
      
      const allAudits = mockDb.getMockAudits();
      const prevAudits = allAudits.filter(a => 
        a.target === audit.target && 
        a.status === 'completed' && 
        a.id !== audit.id &&
        new Date(a.created_at) <= new Date(audit.created_at)
      );
      
      const { generateClientPdf } = await import('./pdfGenerator');
      return generateClientPdf(audit as any, findings as any, prevAudits as any);
    }
    try {
      const res: AxiosResponse<Blob> = await api.get(`/api/reports/${id}/download`, {
        responseType: 'blob',
      });
      return res.data;
    } catch (err) {
      console.error("Error al descargar reporte de API, intentando generar PDF local...", err);
      try {
        const reports = mockDb.getMockReports();
        const report = reports.find(r => r.id === Number(id));
        if (report) {
          const audit = mockDb.getMockAudit(report.audit_id);
          if (audit) {
            const findings = mockDb.getMockFindings(report.audit_id);
            const allAudits = mockDb.getMockAudits();
            const prevAudits = allAudits.filter(a => 
              a.target === audit.target && 
              a.status === 'completed' && 
              a.id !== audit.id &&
              new Date(a.created_at) <= new Date(audit.created_at)
            );
            const { generateClientPdf } = await import('./pdfGenerator');
            return generateClientPdf(audit as any, findings as any, prevAudits as any);
          }
        }
      } catch (innerErr) {
        console.error("Error al generar PDF local alternativo", innerErr);
      }
      const dummyPdfContent = "%PDF-1.4 ... (Reporte Simulado de Ciberseguridad AuditShield) ...";
      return new Blob([dummyPdfContent], { type: 'application/pdf' });
    }
  },

  delete: async (id: number | string): Promise<void> => {
    const numericId = typeof id === 'string' ? parseInt(id) : id;
    if (isDemoMode()) {
      mockDb.deleteMockReport(numericId);
      return;
    }
    try {
      await api.delete(`/api/reports/${id}`);
    } catch (err) {
      mockDb.deleteMockReport(numericId);
    }
  },
};

export default api;
