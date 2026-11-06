import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { ProtectedRoute } from '../components/ProtectedRoute';
import { AppLayout } from '../layouts/AppLayout';
import { Splash } from '../pages/Splash';
import { Login } from '../pages/Login';
import { Dashboard } from '../pages/Dashboard';
import { LiveTrafficLayer1 } from '../pages/LiveTrafficLayer1';
import { Monitoring } from '../pages/Monitoring';
import { InternalNetworkLayer2 } from '../pages/InternalNetworkLayer2';
import { ThreatDetection } from '../pages/ThreatDetection';
import { Incidents } from '../pages/Incidents';
import { Sensors } from '../pages/Sensors';
import { Rules } from '../pages/Rules';
import { DeviceQuarantine } from '../pages/DeviceQuarantine';
import { Reports } from '../pages/Reports';
import { Settings } from '../pages/Settings';
import { AIPerformance } from '../pages/AIPerformance';
import { Users } from '../pages/Users';
import { History } from '../pages/History';
import { Terms } from '../pages/Terms';
import { NotFound } from '../pages/NotFound';

export const AppRouter = () => {
  return (
    <Routes>
      {/* Root Route: Splash Screen */}
      <Route path="/" element={<Splash />} />

      {/* Authentication & Compliance */}
      <Route path="/login" element={<Login />} />
      <Route path="/terms" element={<Terms />} />

      {/* Authenticated Application Routes (Protected via AppLayout) */}
      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        {/* 01. Overview - Threat summary and network health */}
        <Route path="/overview" element={<Dashboard />} />
        <Route path="/dashboard" element={<Dashboard />} />

        {/* 02. Live Events - Recent network activity */}
        <Route path="/live-events" element={<LiveTrafficLayer1 />} />
        <Route path="/traffic-layer1" element={<LiveTrafficLayer1 />} />
        <Route path="/monitoring" element={<Monitoring />} />

        {/* 03. Threats - Detection alerts and classifications */}
        <Route path="/threats" element={<ThreatDetection />} />
        <Route path="/threat-detection" element={<ThreatDetection />} />

        {/* 04. Incidents - Correlated security investigations */}
        <Route path="/incidents" element={<Incidents />} />

        {/* 05. Network - Devices, IPs and connections */}
        <Route path="/network" element={<InternalNetworkLayer2 />} />
        <Route path="/network-layer2" element={<InternalNetworkLayer2 />} />
        <Route path="/internal-network" element={<InternalNetworkLayer2 />} />
        <Route path="/analytics" element={<InternalNetworkLayer2 />} />

        {/* 06. Sensors - Monitoring status and health */}
        <Route path="/sensors" element={<Sensors />} />
        <Route path="/management" element={<Sensors />} />

        {/* 07. Rules - Detection configuration */}
        <Route path="/rules" element={<Rules />} />

        {/* 08. Reports - Historical analysis */}
        <Route path="/reports" element={<Reports />} />

        {/* 09. Settings - Users, roles and organisation settings */}
        <Route path="/settings" element={<Settings />} />

        {/* Quarantine & Response Controls */}
        <Route path="/quarantine" element={<DeviceQuarantine />} />

        {/* Legacy redirect for reports-settings */}
        <Route path="/reports-settings" element={<Navigate to="/reports" replace />} />

        {/* Secondary / Admin Routes */}
        <Route path="/ai-performance" element={<AIPerformance />} />
        <Route path="/history" element={<History />} />
        <Route
          path="/users"
          element={
            <ProtectedRoute requiredCapability="MANAGE_USERS">
              <Users />
            </ProtectedRoute>
          }
        />
      </Route>

      {/* 404 Fallback */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
};

export default AppRouter;
