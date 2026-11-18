export type Page<T> = { items: T[]; total: number; limit: number; offset: number }

export type Service = {
  id: number
  name: string
  owner: string
  tier: number
  internet_facing: boolean
  description: string
  ecosystem: string
  root_path?: string | null
}

export type Finding = {
  id: number
  service_id: number
  service_name: string
  advisory_id: string
  summary: string
  package_name: string
  package_path: string
  installed_version: string
  source_severity: string | null
  display_severity: string | null
  priority: string
  risk_score: number
  risk_breakdown: { factor: string; contribution: number; explanation: string }[]
  dev_only: boolean
  status: string
  withdrawn: boolean
  owner: string | null
  due_date: string | null
  fixed_version: string | null
  upgrade_complexity: string
}

export type Overview = {
  total_services: number
  total_packages_scanned: number
  total_vulnerabilities: number
  critical_vulnerabilities: number
  open_findings: number
  resolved_findings: number
  overdue_findings: number
  severity_distribution: Record<string, number>
  risk_trend: { date: string; active_findings: number }[]
  most_affected_services: { service: string; active_findings: number }[]
  recent_vulnerabilities: { finding_id: number; service: string; package: string; advisory_id: string; discovered_at: string; dev_only: boolean }[]
  recent_remediation_activity: { event_type: string; finding_id: number; service_id: number; created_at: string }[]
  services_needing_attention: { service_id: number; service: string; reasons: string[] }[]
  latest_scan: { id: number; service_id: number; status: string; started_at: string; completed_at: string | null; package_count: number } | null
}

export type Scan = {
  id: number
  service_id: number
  status: string
  started_at: string
  completed_at: string | null
  duration_seconds: number | null
  package_count: number
  vulnerable_count: number
  unverified_count: number
  current_file: string | null
  progress_percent: number
  packages_inspected: number
  vulnerabilities_discovered: number
  error: string | null
}

export type WebhookDelivery = {
  id: number
  event_type: string
  finding_id: number | null
  payload: Record<string, unknown>
  response_status: number | null
  response: Record<string, unknown> | null
  success: boolean
  error: string | null
  created_at: string
}

export type Dependency = {
  name: string
  ecosystem: string
  version: string | null
  specifier: string | null
  resolved: boolean
  direct: boolean
  transitive: boolean
  dev_only: boolean
  package_path: string
  manifest_file: string
  chain: string[]
}
