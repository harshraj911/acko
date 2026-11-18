import { Route, Routes } from 'react-router-dom'
import { AppProvider } from './features/shell/AppContext'
import { AppShell } from './features/shell/AppShell'
import { OverviewPage } from './features/dashboard/OverviewPage'
import { ServiceDetailPage } from './features/services/ServiceDetailPage'
import { ServiceRegistryPage } from './features/services/ServiceRegistryPage'
import { ScanCentrePage } from './features/scanner/ScanCentrePage'
import { PlaceholderPage } from './features/pages/PlaceholderPage'

export default function App() {
  return <AppProvider><Routes><Route element={<AppShell />}>
    <Route index element={<OverviewPage />} />
    <Route path="services" element={<ServiceRegistryPage />} />
    <Route path="services/:serviceId" element={<ServiceDetailPage />} />
    <Route path="scan" element={<ScanCentrePage />} />
    <Route path="explorer" element={<PlaceholderPage index="03" title="Dependency explorer" description="Interactive graph controls and path expansion are scheduled for the next frontend increment." />} />
    <Route path="vulnerabilities" element={<PlaceholderPage index="04" title="Vulnerability centre" description="Advisory browsing, range inspection and remediation recommendations will be implemented in the next step." />} />
    <Route path="findings" element={<PlaceholderPage index="05" title="Findings management" description="Finding workflow, assignment and resolution controls will be implemented in the next step." />} />
    <Route path="analytics" element={<PlaceholderPage index="06" title="Security analytics" description="Dedicated chart exploration and filtering will be implemented in the next step. Overview analytics use live API data." />} />
    <Route path="activity" element={<PlaceholderPage index="07" title="Activity logs" description="Searchable activity timeline controls will be implemented in the next step." />} />
    <Route path="settings" element={<PlaceholderPage index="08" title="Settings" description="Operator settings and integration controls will be implemented in the next step." />} />
    <Route path="*" element={<PlaceholderPage index="404" title="Route not found" description="This route is not part of the current product surface." />} />
  </Route></Routes></AppProvider>
}
