import type { Dependency, Finding, Overview, Page, Scan, Service, WebhookDelivery } from '../types/api'

const API = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8080').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API}/api${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch { /* response may not contain JSON */ }
    throw new Error(detail)
  }
  return response.json() as Promise<T>
}

export const api = {
  overview: () => request<Overview>('/overview'),
  services: (params = new URLSearchParams()) => request<Page<Service>>(`/services?${params}`),
  service: (id: number) => request<Service>(`/services/${id}`),
  createService: (body: Partial<Service>) => request<Service>('/services', { method: 'POST', body: JSON.stringify(body) }),
  updateService: (id: number, body: Partial<Service>) => request<Service>(`/services/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  dependencies: (id: number) => request<Page<Dependency>>(`/services/${id}/dependencies?limit=500`),
  findings: (params = new URLSearchParams()) => request<Page<Finding>>(`/findings?${params}`),
  scans: (params = new URLSearchParams()) => request<Page<Scan>>(`/scans?${params}`),
  startScan: (serviceId?: number) => serviceId
    ? request<{ scan_id: number; status: string }>(`/services/${serviceId}/scan`, { method: 'POST' })
    : request<{ batch_id: number; scan_ids: number[]; status: string }>('/scans', { method: 'POST' }),
  scanProgress: (id: number) => request<Record<string, unknown>>(`/scans/${id}/progress`),
  batchProgress: (id: number) => request<Record<string, unknown>>(`/scan-batches/${id}/progress`),
  deliveries: () => request<Page<WebhookDelivery>>('/webhooks/deliveries?limit=50'),
  overdue: () => request<Array<{ finding_id: number; service_id: number; owner: string; due_date: string }>>('/findings/overdue'),
  graph: (serviceId: number) => request<{ nodes: Record<string, unknown>[]; edges: Record<string, unknown>[]; vulnerable_chains: unknown[] }>(`/services/${serviceId}/graph`),
  serviceFindings: (id: number) => request<Page<Finding>>(`/findings?service_id=${id}&limit=100`),
  assignment: (id: number, owner: string) => request(`/findings/${id}/assignment`, { method: 'PATCH', body: JSON.stringify({ owner, actor: 'operator' }) }),
  status: (id: number, status: string) => request(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status, actor: 'operator' }) }),
}

export const apiUrl = API
