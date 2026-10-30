import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { Shell } from './components/Shell';
import './index.css';
import { AuthProvider } from './lib/auth';
import { Agent360 } from './pages/Agent360';
import { CommandCenter } from './pages/CommandCenter';
import { Discovery } from './pages/Discovery';
import { Enforcement } from './pages/Enforcement';
import { Ledger } from './pages/Ledger';
import { LiveTraffic } from './pages/LiveTraffic';
import { Login } from './pages/Login';
import { Policies } from './pages/Policies';
import { Propose } from './pages/Propose';
import { Registry } from './pages/Registry';
import { Tenant } from './pages/Tenant';
import { Tools } from './pages/Tools';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <AuthProvider>
              <Shell />
            </AuthProvider>
          }
        >
          <Route index element={<CommandCenter />} />
          <Route path="agents" element={<Registry />} />
          <Route path="agents/new" element={<Propose />} />
          <Route path="agents/:id" element={<Agent360 />} />
          <Route path="discovery" element={<Discovery />} />
          <Route path="live" element={<LiveTraffic />} />
          <Route path="enforcement" element={<Enforcement />} />
          <Route path="ledger" element={<Ledger />} />
          <Route path="policies" element={<Policies />} />
          <Route path="tools" element={<Tools />} />
          <Route path="tenant" element={<Tenant />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
