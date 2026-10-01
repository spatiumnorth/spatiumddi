import { Routes, Route, Navigate, useParams } from "react-router-dom";

import { AppLayout } from "@/components/layout/AppLayout";
import { useBrandDocumentTitle } from "@/hooks/usePublicSettings";
import { LoginPage } from "@/pages/LoginPage";
import { LoginCallbackPage } from "@/pages/LoginCallbackPage";
import { ChangePasswordPage } from "@/pages/ChangePasswordPage";
import { AccountPage } from "@/pages/AccountPage";
import { AppliancePage } from "@/pages/appliance/AppliancePage";
import { SetupWizardPage } from "@/pages/appliance/SetupWizardPage";
import { DashboardPage } from "@/pages/DashboardPage";
import { IPAMPage } from "@/pages/ipam/IPAMPage";
import { NATPage } from "@/pages/ipam/NATPage";
import { StaleIPReportPage } from "@/pages/ipam/StaleIPReportPage";
import { DNSSECPoliciesPage } from "@/pages/dns/DNSSECPoliciesPage";
import { DNSPage } from "@/pages/dns/DNSPage";
import { DNSPoolsPage } from "@/pages/dns/DNSPoolsPage";
import { VLANsPage } from "@/pages/vlans/VLANsPage";
import { VRFsPage } from "@/pages/vrfs/VRFsPage";
import { VRFDetailPage } from "@/pages/vrfs/VRFDetailPage";
import { DHCPPage } from "@/pages/dhcp/DHCPPage";
import { PXEProfilesPage } from "@/pages/dhcp/PXEProfilesPage";
import { KubernetesPage } from "@/pages/kubernetes/KubernetesPage";
import { DockerPage } from "@/pages/docker/DockerPage";
import { ProxmoxPage } from "@/pages/proxmox/ProxmoxPage";
import { OpnsensePage } from "@/pages/opnsense/OpnsensePage";
import { PanosPage } from "@/pages/panos/PanosPage";
import { FortinetPage } from "@/pages/fortinet/FortinetPage";
import { MerakiPage } from "@/pages/meraki/MerakiPage";
import { FirewallFeedsPage } from "@/pages/firewall_feeds/FirewallFeedsPage";
import { CloudPage } from "@/pages/cloud/CloudPage";
import { NetbirdPage } from "@/pages/netbird/NetbirdPage";
import { TailscalePage } from "@/pages/tailscale/TailscalePage";
import { UnifiPage } from "@/pages/unifi/UnifiPage";
import { UnifiControllerDetailPage } from "@/pages/unifi/UnifiControllerDetailPage";
import { NetworkPage } from "@/pages/network/NetworkPage";
import { DeviceDetailView } from "@/pages/network/DeviceDetailView";
import { AsnsPage } from "@/pages/network/AsnsPage";
import { AsnDetailPage } from "@/pages/network/AsnDetailPage";
import { AVFlowsPage } from "@/pages/network/AVFlowsPage";
import { BACnetDevicesPage } from "@/pages/network/BACnetDevicesPage";
import { DICOMPage } from "@/pages/network/DICOMPage";
import { E911Page } from "@/pages/network/E911Page";
import { OTDevicesPage } from "@/pages/network/OTDevicesPage";
import { CertificatesPage } from "@/pages/network/CertificatesPage";
import { CircuitsPage } from "@/pages/network/CircuitsPage";
import { LookingGlassPage } from "@/pages/network/looking-glass/LookingGlassPage";
import { MulticastGroupsPage } from "@/pages/network/MulticastGroupsPage";
import { CustomersPage } from "@/pages/network/CustomersPage";
import { OverlaysPage } from "@/pages/network/OverlaysPage";
import { OverlayDetailPage } from "@/pages/network/OverlayDetailPage";
import { ProvidersPage } from "@/pages/network/ProvidersPage";
import { ServicesPage } from "@/pages/network/ServicesPage";
import { SitesPage } from "@/pages/network/SitesPage";
import { NmapToolsPage } from "@/pages/nmap/NmapToolsPage";
import { PacketCapturePage } from "@/pages/pcap/PacketCapturePage";
import { NetworkToolsPage } from "@/pages/tools/NetworkToolsPage";
import { CidrCalculatorPage } from "@/pages/tools/CidrCalculatorPage";
import { WakeSchedulesPage } from "@/pages/tools/WakeSchedulesPage";
import { NewDevicesPage } from "@/pages/security/NewDevicesPage";
import { BlockSyncPage } from "@/pages/security/BlockSyncPage";
import { SubnetPlannerListPage } from "@/pages/ipam/SubnetPlannerListPage";
import { SubnetPlannerEditorPage } from "@/pages/ipam/SubnetPlannerEditorPage";
import { LogsPage } from "@/pages/LogsPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { UsersPage } from "@/pages/admin/UsersPage";
import { AuditPage } from "@/pages/admin/AuditPage";
import { ImportPage } from "@/pages/admin/ImportPage";
import { BackupPage } from "@/pages/admin/BackupPage";
import { DiagnosticsErrorsPage } from "@/pages/admin/DiagnosticsErrorsPage";
import { AIProvidersPage } from "@/pages/admin/AIProvidersPage";
import { AIPromptsPage } from "@/pages/admin/AIPromptsPage";
import { AIToolCatalogPage } from "@/pages/admin/AIToolCatalogPage";
import { FeaturesPage } from "@/pages/admin/FeaturesPage";
import { CustomFieldsPage } from "@/pages/admin/CustomFieldsPage";
import { IPAMTemplatesPage } from "@/pages/admin/IPAMTemplatesPage";
import { ApiTokensPage } from "@/pages/admin/ApiTokensPage";
import { SessionsPage } from "@/pages/admin/SessionsPage";
import { AlertsPage } from "@/pages/admin/AlertsPage";
import { DNSBLPage } from "@/pages/admin/DNSBLPage";
import { AuthProvidersPage } from "@/pages/admin/AuthProvidersPage";
import { DomainsPage } from "@/pages/admin/DomainsPage";
import { DomainDetailPage } from "@/pages/admin/DomainDetailPage";
import { GroupsPage } from "@/pages/admin/GroupsPage";
import { RolesPage } from "@/pages/admin/RolesPage";
import { CompliancePage } from "@/pages/admin/CompliancePage";
import { ConformityPage } from "@/pages/admin/ConformityPage";
import { TrashPage } from "@/pages/admin/TrashPage";
import { WebhooksPage } from "@/pages/admin/WebhooksPage";
import { ChangeRequestsPage } from "@/pages/admin/ChangeRequestsPage";
import RequestsPage from "@/pages/RequestsPage";
import { PlatformInsightsPage } from "@/pages/admin/PlatformInsightsPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { useAuth } from "@/hooks/useAuth";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, bootstrapping } = useAuth();
  // On a full page reload the in-memory access token is gone; the app runs
  // one silent /auth/refresh against the HttpOnly cookie (#484). Render a
  // loader until it resolves so a real session isn't bounced to /login.
  if (bootstrapping) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <p className="text-sm text-muted-foreground">Restoring session…</p>
      </div>
    );
  }
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

// Network device ids are UUIDs (`network_device.id`).
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Legacy device-detail bookmark (/network/:id, pre-#84). Redirects a
 * device id to its canonical /network/devices/:id; anything else under
 * /network that matches no real page — a typo like /network/vlna — is a
 * 404, not a device lookup for "vlna" (#1360).
 */
function LegacyDeviceRoute() {
  const { id = "" } = useParams<{ id: string }>();
  if (!UUID_RE.test(id)) return <NotFoundPage />;
  return <Navigate to={`/network/devices/${id}`} replace />;
}

export default function App() {
  // Issue #888 — keep the browser tab on the operator's configured title.
  useBrandDocumentTitle();

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/login/callback" element={<LoginCallbackPage />} />
      <Route path="/change-password" element={<ChangePasswordPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="account" element={<AccountPage />} />
        <Route path="appliance" element={<AppliancePage />} />
        <Route path="appliance/setup" element={<SetupWizardPage />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="ipam" element={<IPAMPage />} />
        <Route path="ipam/nat" element={<NATPage />} />
        <Route path="ipam/stale" element={<StaleIPReportPage />} />
        <Route path="ipam/plans" element={<SubnetPlannerListPage />} />
        <Route path="ipam/plans/:id" element={<SubnetPlannerEditorPage />} />
        <Route path="dns" element={<DNSPage />} />
        <Route path="dns/pools" element={<DNSPoolsPage />} />
        <Route path="dns/dnssec-policies" element={<DNSSECPoliciesPage />} />
        {/* Network section — Devices / VLANs / VRFs / ASNs. The old top-
            level /network and /vlans paths redirect here so existing
            bookmarks keep working. See issue #84. */}
        <Route
          path="network"
          element={<Navigate to="/network/devices" replace />}
        />
        <Route path="network/devices" element={<NetworkPage />} />
        <Route path="network/devices/:id" element={<DeviceDetailView />} />
        <Route path="network/vlans" element={<VLANsPage />} />
        <Route path="network/vrfs" element={<VRFsPage />} />
        <Route path="network/vrfs/:id" element={<VRFDetailPage />} />
        <Route path="network/asns" element={<AsnsPage />} />
        <Route path="network/asns/:id" element={<AsnDetailPage />} />
        {/* Vertical network-awareness surfaces (#543): AV over IP (#540),
            BACnet/IP (#541), OT / industrial (#542). */}
        <Route path="network/av" element={<AVFlowsPage />} />
        <Route path="network/bacnet" element={<BACnetDevicesPage />} />
        <Route path="network/dicom" element={<DICOMPage />} />
        <Route path="network/e911" element={<E911Page />} />
        <Route path="network/ot" element={<OTDevicesPage />} />
        <Route path="network/certificates" element={<CertificatesPage />} />
        <Route path="network/circuits" element={<CircuitsPage />} />
        <Route path="network/customers" element={<CustomersPage />} />
        <Route path="network/looking-glass" element={<LookingGlassPage />} />
        <Route path="network/multicast" element={<MulticastGroupsPage />} />
        {/* Old separate-route deep links redirect to the sub-tab so
            existing bookmarks keep working. */}
        <Route
          path="network/multicast/domains"
          element={<Navigate to="/network/multicast?tab=domains" replace />}
        />
        <Route path="network/overlays" element={<OverlaysPage />} />
        <Route path="network/overlays/:id" element={<OverlayDetailPage />} />
        <Route path="network/providers" element={<ProvidersPage />} />
        <Route path="network/services" element={<ServicesPage />} />
        <Route path="network/sites" element={<SitesPage />} />
        <Route
          path="vlans"
          element={<Navigate to="/network/vlans" replace />}
        />
        {/* Legacy device-detail bookmark (/network/:id) — preserve by
            redirecting to /network/devices/:id. */}
        <Route path="network/:id" element={<LegacyDeviceRoute />} />
        <Route path="tools/nmap" element={<NmapToolsPage />} />
        <Route path="tools/pcap" element={<PacketCapturePage />} />
        <Route path="tools/network" element={<NetworkToolsPage />} />
        <Route path="tools/cidr" element={<CidrCalculatorPage />} />
        <Route path="tools/wake-schedules" element={<WakeSchedulesPage />} />
        <Route path="security/new-devices" element={<NewDevicesPage />} />
        <Route path="security/block-sync" element={<BlockSyncPage />} />
        <Route path="security/firewall-feeds" element={<FirewallFeedsPage />} />
        <Route path="dhcp" element={<DHCPPage />} />
        <Route path="dhcp/groups/:groupId/pxe" element={<PXEProfilesPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="kubernetes" element={<KubernetesPage />} />
        <Route path="docker" element={<DockerPage />} />
        <Route path="proxmox" element={<ProxmoxPage />} />
        <Route path="opnsense" element={<OpnsensePage />} />
        <Route path="paloalto" element={<PanosPage />} />
        <Route path="fortinet" element={<FortinetPage />} />
        <Route path="meraki" element={<MerakiPage />} />
        <Route path="cloud" element={<CloudPage />} />
        <Route path="netbird" element={<NetbirdPage />} />
        <Route path="tailscale" element={<TailscalePage />} />
        <Route path="unifi" element={<UnifiPage />} />
        <Route path="unifi/:id" element={<UnifiControllerDetailPage />} />
        <Route path="admin/users" element={<UsersPage />} />
        <Route path="admin/groups" element={<GroupsPage />} />
        <Route path="admin/roles" element={<RolesPage />} />
        <Route path="admin/audit" element={<AuditPage />} />
        {/* Configuration → Import hub (#36): one shell with a left sub-nav.
            The legacy per-importer routes render the same shell with the
            matching initialTab so existing deep-links keep working (notably
            the DNS page's navigate("/admin/dns-import", {state: cloudServerId}). */}
        <Route path="admin/import" element={<ImportPage />} />
        <Route
          path="admin/dns-import"
          element={<ImportPage initialTab="dns" />}
        />
        <Route
          path="admin/dhcp-import"
          element={<ImportPage initialTab="dhcp" />}
        />
        <Route
          path="admin/netbox-import"
          element={<ImportPage initialTab="netbox" />}
        />
        <Route
          path="admin/cutover"
          element={<ImportPage initialTab="cutover" />}
        />
        <Route path="admin/backup" element={<BackupPage />} />
        <Route
          path="admin/diagnostics/errors"
          element={<DiagnosticsErrorsPage />}
        />
        <Route path="admin/ai/providers" element={<AIProvidersPage />} />
        <Route path="admin/ai/prompts" element={<AIPromptsPage />} />
        <Route path="admin/ai/tools" element={<AIToolCatalogPage />} />
        <Route path="admin/features" element={<FeaturesPage />} />
        <Route path="admin/custom-fields" element={<CustomFieldsPage />} />
        <Route path="admin/ipam/templates" element={<IPAMTemplatesPage />} />
        <Route path="admin/auth-providers" element={<AuthProvidersPage />} />
        <Route path="admin/api-tokens" element={<ApiTokensPage />} />
        <Route path="admin/sessions" element={<SessionsPage />} />
        <Route path="admin/alerts" element={<AlertsPage />} />
        <Route path="admin/dns-blocklists" element={<DNSBLPage />} />
        <Route path="admin/domains" element={<DomainsPage />} />
        <Route path="admin/domains/:id" element={<DomainDetailPage />} />
        <Route path="admin/webhooks" element={<WebhooksPage />} />
        <Route path="admin/change-requests" element={<ChangeRequestsPage />} />
        {/* #696 self-service portal — deliberately top-level, not under
            admin/: requesters are ordinary users, not administrators. */}
        <Route path="requests" element={<RequestsPage />} />
        <Route path="admin/compliance" element={<CompliancePage />} />
        <Route path="admin/conformity" element={<ConformityPage />} />
        <Route path="admin/trash" element={<TrashPage />} />
        <Route
          path="admin/platform-insights"
          element={<PlatformInsightsPage />}
        />
        <Route
          path="admin/failover-channels"
          element={<Navigate to="/dhcp" replace />}
        />
        <Route path="settings" element={<SettingsPage />} />
        {/* #1360 — catch-all, deliberately the LAST child of the protected
            layout: an unknown URL renders inside the app chrome, and a
            signed-out user is sent to /login by ProtectedRoute like on any
            other page. Without it <Routes> rendered null — a blank page. */}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
