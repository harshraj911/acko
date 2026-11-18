import { ArrowRight, ArrowUpRight, ShieldAlert, Siren } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Button, Counter, EmptyState, ErrorState, Skeleton } from '../../components/ui/Primitives'
import { useApi } from '../../hooks/useApi'
import { api } from '../../services/api'
import type { Overview } from '../../types/api'
import { Wireframe } from '../shell/Wireframe'

const SEVERITY_COLORS: Record<string, string> = { Critical: '#ff3030', High: '#e50932', Medium: '#c8102e', Low: '#686868' }

export function OverviewPage() {
  const navigate = useNavigate()
  const { data, error, loading, reload } = useApi(api.overview)
  const [scanBusy, setScanBusy] = useState(false)

  const initiateScan = async () => {
    setScanBusy(true)
    try {
      const result = await api.startScan()
      navigate(`/scan?batch=${'batch_id' in result ? result.batch_id : ''}`)
    } catch (reason) {
      window.dispatchEvent(new CustomEvent('dw-toast', { detail: { message: reason instanceof Error ? reason.message : 'Could not start scan', kind: 'error' } }))
    } finally { setScanBusy(false) }
  }

  return <div className="overview-page page-pad">
    <section className="hero-panel">
      <div className="hero-grid" />
      <div className="hero-glow" />
      <div className="hero-content">
        <div className="hero-overline"><span className="live-dot" /> SOFTWARE SUPPLY CHAIN INTELLIGENCE <span className="hero-index">/ 001</span></div>
        <h1>YOUR CODE.<br />YOUR DEPENDENCIES.<br /><em>YOUR SECURITY.</em></h1>
        <p>Gain complete visibility into your software supply chain. Discover vulnerabilities, identify exposed services and resolve security risks before they become production incidents.</p>
        <div className="hero-actions"><Button onClick={initiateScan} disabled={scanBusy}>{scanBusy ? 'STARTING SCAN...' : 'INITIATE SECURITY SCAN'} <ArrowRight size={15} /></Button><Link className="button button-outline" to="/explorer">EXPLORE DEPENDENCIES <ArrowUpRight size={14} /></Link></div>
        <div className="hero-footnote"><span>ACKO / ENGINEERING SECURITY</span><span>LOCAL ENVIRONMENT · LIVE DATA</span></div>
      </div>
      <div className="hero-visual"><Wireframe /><div className="hero-visual-cross">+</div><div className="hero-side-note">DEPENDENCY<br />SURFACE / ACTIVE</div></div>
      <div className="hero-corner">DW—OPS / 24.11</div>
    </section>

    <section className="section-block overview-metrics" aria-label="Security overview">
      <div className="section-heading"><div><span className="eyebrow">SYSTEM POSTURE / CURRENT</span><h2>Security overview</h2></div><span className="section-aside"><i className="live-dot" /> LIVE DATABASE SNAPSHOT</span></div>
      {loading ? <div className="metrics-loading"><Skeleton /><Skeleton /><Skeleton /></div> : error ? <ErrorState message={error} retry={reload} /> : data ? <MetricStrip data={data} /> : null}
    </section>

    {!loading && error && <div className="dashboard-error-slot" />}
    {loading ? <DashboardSkeleton /> : error ? null : data ? <DashboardSections data={data} /> : <EmptyState title="No telemetry yet" detail="The overview will populate after the backend finishes its initial scan." />}
  </div>
}

function MetricStrip({ data }: { data: Overview }) {
  const metrics = [
    { value: data.total_services, label: 'REGISTERED SERVICES', mode: 'large' },
    { value: data.total_packages_scanned, label: 'PACKAGES SCANNED', mode: 'large' },
    { value: data.total_vulnerabilities, label: 'ACTIVE VULNERABILITIES', mode: 'alert' },
    { value: data.critical_vulnerabilities, label: 'CRITICAL', mode: 'critical' },
    { value: data.open_findings, label: 'OPEN FINDINGS', mode: 'small' },
    { value: data.resolved_findings, label: 'RESOLVED', mode: 'small' },
    { value: data.overdue_findings, label: 'OVERDUE', mode: 'small' },
  ]
  return <div className="metric-strip">{metrics.map((metric, index) => <div className={`metric-cell metric-${metric.mode}`} key={metric.label}><Counter value={metric.value} label={metric.label} index={index} accent={metric.mode === 'critical'} /></div>)}</div>
}

function DashboardSections({ data }: { data: Overview }) {
  const severity = Object.entries(data.severity_distribution).map(([name, value]) => ({ name, value }))
  return <div className="dashboard-grid">
    <section className="data-panel severity-panel"><PanelHeading index="01" title="Severity distribution" action={<Link to="/vulnerabilities">VIEW CENTRE <ArrowRight size={12} /></Link>} />
      {severity.length ? <div className="severity-chart"><div className="donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={severity} dataKey="value" nameKey="name" innerRadius="70%" outerRadius="91%" paddingAngle={3} stroke="none">{severity.map((item) => <Cell key={item.name} fill={SEVERITY_COLORS[item.name] || '#686868'} />)}</Pie><Tooltip contentStyle={{ background: '#111', border: '1px solid #303030', borderRadius: 0, color: '#f5f5f5', fontFamily: 'Inter' }} /></PieChart></ResponsiveContainer><div className="donut-total"><b>{data.total_vulnerabilities}</b><small>ACTIVE</small></div></div><div className="severity-legend">{severity.map((item) => <div className="severity-legend-row" key={item.name}><i style={{ background: SEVERITY_COLORS[item.name] || '#686868' }} /><span>{item.name}</span><b>{item.value}</b><small>{data.total_vulnerabilities ? Math.round(item.value / data.total_vulnerabilities * 100) : 0}%</small></div>)}</div></div> : <EmptyState title="No active findings" detail="Severity distribution will appear when scans discover vulnerabilities." />}
    </section>
    <section className="data-panel trend-panel"><PanelHeading index="02" title="Risk trend" action={<span className="chart-unit">ACTIVE FINDINGS / DAY</span>} />
      {data.risk_trend.length ? <div className="trend-chart"><ResponsiveContainer width="100%" height="100%"><AreaChart data={data.risk_trend} margin={{ top: 12, right: 8, left: -24, bottom: 0 }}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#e50932" stopOpacity={.34} /><stop offset="100%" stopColor="#e50932" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#242424" strokeDasharray="2 5" vertical={false} /><XAxis dataKey="date" tick={{ fill: '#777', fontSize: 10 }} axisLine={{ stroke: '#303030' }} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: '#777', fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#111', border: '1px solid #303030', borderRadius: 0, color: '#f5f5f5', fontFamily: 'Inter' }} /><Area type="monotone" dataKey="active_findings" stroke="#e50932" strokeWidth={2} fill="url(#riskFill)" activeDot={{ r: 4, fill: '#e50932', stroke: '#080808', strokeWidth: 2 }} /></AreaChart></ResponsiveContainer></div> : <EmptyState title="History is short" detail="Risk trend will grow as subsequent scans and finding events are recorded." />}
      <div className="chart-foot"><span><i className="legend-line" /> ACTIVE FINDINGS</span><span>HISTORY / {data.risk_trend.length} DAY{data.risk_trend.length === 1 ? '' : 'S'}</span></div>
    </section>
    <section className="data-panel affected-panel"><PanelHeading index="03" title="Most affected services" action={<Link to="/services">REGISTRY <ArrowRight size={12} /></Link>} />
      {data.most_affected_services.length ? <div className="affected-list">{data.most_affected_services.map((item, index) => <Link to={`/services?search=${encodeURIComponent(item.service)}`} className="affected-row" key={item.service}><span className="rank">0{index + 1}</span><span className="affected-name">{item.service}<small>ACTIVE EXPOSURES</small></span><div className="affected-bar"><i style={{ width: `${Math.max(7, item.active_findings / Math.max(data.most_affected_services[0]?.active_findings || 1, 1) * 100)}%` }} /></div><b>{item.active_findings.toString().padStart(2, '0')}</b></Link>)}</div> : <EmptyState title="No affected services" detail="No active findings are currently associated with a service." />}
    </section>
    <section className="data-panel recent-panel"><PanelHeading index="04" title="Recently discovered" action={<Link to="/findings">ALL FINDINGS <ArrowRight size={12} /></Link>} />
      {data.recent_vulnerabilities.length ? <div className="recent-list">{data.recent_vulnerabilities.slice(0, 5).map((item) => <Link to={`/findings?search=${encodeURIComponent(item.advisory_id)}`} className="recent-row" key={item.finding_id}><span className="recent-severity"><ShieldAlert size={15} /></span><span className="recent-copy"><b>{item.package}<span className="font-mono"> / {item.advisory_id}</span></b><small>{item.service} · {timeAgo(item.discovered_at)}{item.dev_only ? ' · DEV ONLY' : ''}</small></span><ArrowUpRight size={14} /></Link>)}</div> : <EmptyState title="No recent discoveries" detail="New vulnerability matches will appear here." />}
    </section>
    <section className="data-panel remediation-panel"><PanelHeading index="05" title="Remediation activity" action={<Link to="/activity">ACTIVITY LOG <ArrowRight size={12} /></Link>} />
      {data.recent_remediation_activity.length ? <div className="activity-list">{data.recent_remediation_activity.slice(0, 5).map((item, index) => <div className="activity-row" key={`${item.finding_id}-${index}`}><span className="activity-stem"><i /></span><div><b>{humanize(item.event_type)}</b><small>Finding #{item.finding_id} · {timeAgo(item.created_at)}</small></div></div>)}</div> : <EmptyState title="No remediation activity" detail="Resolved and updated findings will be recorded here." />}
    </section>
    <section className="data-panel attention-panel"><PanelHeading index="06" title="Immediate attention" action={<Link to="/findings?priority=Critical">PRIORITIZE <ArrowRight size={12} /></Link>} />
      {data.services_needing_attention.length ? <div className="attention-list">{data.services_needing_attention.slice(0, 4).map((item) => <Link to={`/services/${item.service_id}`} className="attention-row" key={item.service_id}><span className="attention-icon"><Siren size={16} /></span><span><b>{item.service}</b><small>{item.reasons.join(' · ')}</small></span><ArrowRight size={14} /></Link>)}</div> : <EmptyState title="No immediate risks" detail="No high or critical priority findings need attention." />}
    </section>
    <section className="data-panel latest-panel"><PanelHeading index="07" title="Latest scan" action={<Link to="/scan">COMMAND CENTRE <ArrowRight size={12} /></Link>} />
      {data.latest_scan ? <div className="latest-scan-line"><span className="latest-scan-status"><span className="live-dot" /> {data.latest_scan.status.toUpperCase()}</span><span className="font-mono">SCAN / {data.latest_scan.id.toString().padStart(4, '0')}</span><b>{data.latest_scan.package_count} <small>PACKAGES</small></b><span>{data.latest_scan.completed_at ? timeAgo(data.latest_scan.completed_at) : 'IN PROGRESS'}</span></div> : <EmptyState title="No scans yet" detail="Start a real scan to build the inventory." />}
    </section>
  </div>
}

function PanelHeading({ index, title, action }: { index: string; title: string; action?: React.ReactNode }) {
  return <div className="panel-heading"><span className="panel-index">{index}</span><h3>{title}</h3>{action && <div className="panel-action">{action}</div>}</div>
}

function DashboardSkeleton() { return <div className="dashboard-grid">{Array.from({ length: 7 }, (_, index) => <div className="data-panel" key={index}><Skeleton className="skeleton-title" /><Skeleton className="skeleton-chart" /></div>)}</div> }
function timeAgo(value: string) { const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000)); if (seconds < 60) return 'just now'; if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`; return `${Math.floor(seconds / 86400)}d ago` }
function humanize(value: string) { return value.replaceAll('.', ' ').replaceAll('_', ' ').replace(/^./, (character) => character.toUpperCase()) }
