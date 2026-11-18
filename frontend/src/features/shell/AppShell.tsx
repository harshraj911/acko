import { AnimatePresence, motion } from 'framer-motion'
import { Activity, Bell, Boxes, ChartNoAxesCombined, ChevronDown, CircleUserRound, Command, FileWarning, GitFork, LayoutDashboard, Menu, Search, Settings, ShieldAlert, X } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { api } from '../../services/api'
import type { WebhookDelivery } from '../../types/api'
import { useApp } from './AppContext'
import { Logo } from './Logo'

const navigation = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Service Registry', to: '/services', icon: Boxes },
  { label: 'Dependency Explorer', to: '/explorer', icon: GitFork },
  { label: 'Vulnerability Centre', to: '/vulnerabilities', icon: ShieldAlert },
  { label: 'Findings Management', to: '/findings', icon: FileWarning },
  { label: 'Security Analytics', to: '/analytics', icon: ChartNoAxesCombined },
  { label: 'Activity Logs', to: '/activity', icon: Activity },
  { label: 'Settings', to: '/settings', icon: Settings },
]

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [menu, setMenu] = useState<'notifications' | 'profile' | null>(null)
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([])
  const [overdue, setOverdue] = useState<{ finding_id: number; service_id: number; owner: string; due_date: string }[]>([])
  const [globalSearch, setGlobalSearch] = useState('')
  const location = useLocation()
  const { notify } = useApp()

  useEffect(() => {
    Promise.all([api.deliveries(), api.overdue()]).then(([deliveryPage, overdueRows]) => {
      setDeliveries(deliveryPage.items.slice(0, 5))
      setOverdue(overdueRows)
    }).catch(() => undefined)
  }, [location.pathname])

  const current = navigation.find((item) => item.to === location.pathname) || (location.pathname.startsWith('/services/') ? navigation[1] : navigation[0])
  const crumb = useMemo(() => location.pathname.split('/').filter(Boolean).map((part) => part.replaceAll('-', ' ')), [location.pathname])

  const sidebar = <>
    <div className="sidebar-brand"><Logo compact={collapsed} /><button className="sidebar-toggle" onClick={() => setCollapsed((value) => !value)} aria-label="Toggle sidebar"><Menu size={17} /></button></div>
    <div className="sidebar-section-label">WORKSPACE <span>08</span></div>
    <nav className="sidebar-nav">{navigation.map(({ label, to, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `nav-item ${isActive ? 'nav-active' : ''}`} title={collapsed ? label : undefined}><Icon size={17} strokeWidth={1.7} /><span>{label}</span><i className="nav-active-mark" /></NavLink>)}</nav>
    <div className="sidebar-bottom"><div className="connection-line"><span className="live-dot" /> API CONNECTION <b>LIVE</b></div><div className="sidebar-version">DEPENDENCY WATCH <span>v0.1.0 / LOCAL</span></div></div>
  </>

  return <div className={`app-shell ${collapsed ? 'shell-collapsed' : ''}`}>
    <aside className="sidebar desktop-sidebar">{sidebar}</aside>
    <AnimatePresence>{mobileOpen && <motion.div className="mobile-scrim" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setMobileOpen(false)}><motion.aside className="sidebar mobile-sidebar" initial={{ x: -280 }} animate={{ x: 0 }} exit={{ x: -280 }} onClick={(event) => event.stopPropagation()}>{sidebar}<button className="mobile-close" onClick={() => setMobileOpen(false)}><X size={20} /></button></motion.aside></motion.div>}</AnimatePresence>
    <main className="workspace">
      <header className="topbar">
        <button className="mobile-menu icon-button" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={19} /></button>
        <div className="breadcrumbs"><span>SECURITY OPERATIONS</span><b>/</b><strong>{current.label.toUpperCase()}</strong>{crumb.length > 1 && <><b>/</b><small>{crumb.at(-1)?.toUpperCase()}</small></>}</div>
        <label className="global-search"><Search size={15} /><input placeholder="Search services, packages, advisories..." value={globalSearch} onChange={(event) => setGlobalSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter' && globalSearch.trim()) { window.location.href = `/services?search=${encodeURIComponent(globalSearch)}` } }} /><kbd><Command size={11} /> K</kbd></label>
        <div className="top-actions">
          <div className="menu-anchor"><button className={`icon-button notification-button ${menu === 'notifications' ? 'icon-active' : ''}`} aria-label="Notifications" onClick={() => setMenu(menu === 'notifications' ? null : 'notifications')}><Bell size={17} />{overdue.length + deliveries.length > 0 && <i />}</button>
            <AnimatePresence>{menu === 'notifications' && <motion.div className="popover notification-popover" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 5 }}><div className="popover-head"><div><small>LIVE FEED</small><strong>Notifications</strong></div><span className="live-dot" /></div><div className="notice-section"><span className="eyebrow">OVERDUE FINDINGS · {overdue.length}</span>{overdue.length ? overdue.slice(0, 4).map((item) => <Link to={`/findings?search=${item.finding_id}`} className="notice-row" key={`o-${item.finding_id}`}><i className="notice-alert" /><span><b>Finding #{item.finding_id} overdue</b><small>Owner {item.owner || 'unassigned'}</small></span></Link>) : <p className="popover-empty">No overdue findings.</p>}</div><div className="notice-section"><span className="eyebrow">RECENT DELIVERY · {deliveries.length}</span>{deliveries.length ? deliveries.slice(0, 4).map((item) => <div className="notice-row" key={`d-${item.id}`}><i className={item.success ? 'notice-good' : 'notice-alert'} /><span><b>{item.event_type.replaceAll('.', ' ')}</b><small>Finding #{item.finding_id ?? 'test'} · {item.success ? 'delivered' : 'failed'}</small></span></div>) : <p className="popover-empty">No notifications delivered.</p>}</div></motion.div>}</AnimatePresence>
          </div>
          <span className="top-divider" />
          <div className="menu-anchor"><button className="profile-trigger" onClick={() => setMenu(menu === 'profile' ? null : 'profile')}><span className="profile-avatar"><CircleUserRound size={17} /></span><span className="profile-copy"><b>Security Operator</b><small>LOCAL INSTANCE</small></span><ChevronDown size={13} /></button>{menu === 'profile' && <div className="popover profile-popover"><span className="eyebrow">ACTIVE SESSION</span><b>Security Operator</b><small>Local demonstration workspace</small><button onClick={() => { setMenu(null); notify('Profile settings are not configured in this local build.', 'info') }}>Session details</button></div>}</div>
        </div>
      </header>
      <div className="route-stage"><AnimatePresence mode="wait"><motion.div key={location.pathname} className="route-content" initial={{ opacity: 0, y: 7 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} transition={{ duration: .16 }}><Outlet /></motion.div></AnimatePresence></div>
    </main>
  </div>
}
