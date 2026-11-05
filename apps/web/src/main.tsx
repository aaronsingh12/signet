import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import './index.css';
import { AuthProvider } from './lib/auth';
import { AddAgentFlow, AddAgentStart, AddPlatform } from './pages/AddAgent';
import { Agent360 } from './pages/Agent360';
import { AgentSettings } from './pages/AgentSettings';
import { AgentSetup } from './pages/AgentSetup';
import { Approvals, MobileApproval } from './pages/Approvals';
import { CommandCenter } from './pages/CommandCenter';
import { Connectors } from './pages/Connectors';
import { Discovery } from './pages/Discovery';
import { Enforcement } from './pages/Enforcement';
import { Login } from './pages/Login';
import { Plugins } from './pages/Plugins';
import { Policies } from './pages/Policies';
import { Registry } from './pages/Registry';
import { Activity, Moved, Reports, Settings } from './pages/Sections';
import { Tenant } from './pages/Tenant';
import { Tools } from './pages/Tools';

const authed = (element: JSX.Element) => <AuthProvider>{element}</AuthProvider>;

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/m/approvals/:id" element={authed(<MobileApproval />)} />
        {/* The guided path has no menu: one thing to do at a time. */}
        <Route path="/agents/new" element={authed(<AddAgentStart />)} />
        <Route path="/agents/new/one" element={authed(<AddAgentFlow />)} />
        <Route path="/agents/:id/setup" element={authed(<AgentSetup />)} />
        <Route element={authed(<Shell />)}>
          <Route index element={<CommandCenter />} />
          <Route path="agents" element={<Registry />} />
          <Route path="agents/new/platform" element={<AddPlatform />} />
          <Route path="agents/:id" element={<Agent360 />} />
          <Route path="needs-you" element={<Approvals />} />
          <Route path="activity" element={<Activity />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
          <Route path="settings/people" element={<Tenant />} />
          <Route path="settings/apps" element={<Tools />} />
          <Route path="settings/accounts" element={<Plugins />} />
          <Route path="settings/systems" element={<Connectors />} />
          <Route path="settings/rules" element={<Policies />} />
          <Route path="settings/agent-defaults" element={<AgentSettings />} />
          <Route path="settings/discovery" element={<Discovery />} />
          <Route path="settings/safety" element={<Enforcement />} />
          {/* Addresses from stored notifications and bookmarks. */}
          <Route path="approvals" element={<Moved to="/needs-you" />} />
          <Route path="live" element={<Moved to="/activity" />} />
          <Route path="ledger" element={<Moved to="/activity?tab=history" />} />
          <Route path="controls" element={<Moved to="/reports" />} />
          <Route path="agents/quick" element={<Moved to="/agents/new/one" />} />
          <Route path="enforcement" element={<Moved to="/settings/safety" />} />
          <Route path="discovery" element={<Moved to="/settings/discovery" />} />
          <Route path="connectors" element={<Moved to="/settings/systems" />} />
          <Route path="policies" element={<Moved to="/settings/rules" />} />
          <Route path="plugins" element={<Moved to="/settings/accounts" />} />
          <Route path="tools" element={<Moved to="/settings/apps" />} />
          <Route path="tenant" element={<Moved to="/settings/people" />} />
          <Route path="settings/agents" element={<Moved to="/settings/agent-defaults" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
