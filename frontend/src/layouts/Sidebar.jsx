import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  Activity,
  AlertTriangle,
  FolderKanban,
  Network,
  Radio,
  Sliders,
  FileText,
  Settings as SettingsIcon,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';

export const Sidebar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { role } = useAuth();

  const [systemHealth, setSystemHealth] = useState({
    status: 'healthy',
    components: { database: 'online', model_manager: 'online', live_monitor: 'running' },
  });
  const [lastUpdated, setLastUpdated] = useState('Just now');

  useEffect(() => {
    let isMounted = true;
    const fetchHealth = async () => {
      try {
        const res = await api.get('/health');
        if (isMounted && res.data) {
          setSystemHealth(res.data);
          setLastUpdated(new Date().toLocaleTimeString());
        }
      } catch (err) {
        if (isMounted) {
          setSystemHealth((prev) => ({ ...prev, status: 'degraded' }));
        }
      }
    };

    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Section 1: Security Analyst Operations (Threats, evidence, investigations and incidents)
  const analystNavItems = [
    {
      id: 'overview',
      path: '/overview',
      aliases: ['/dashboard'],
      label: 'Overview',
      desc: 'Threat summary & health',
      icon: LayoutDashboard,
    },
    {
      id: 'live-events',
      path: '/live-events',
      aliases: ['/traffic-layer1', '/monitoring'],
      label: 'Live Events',
      desc: 'Recent network activity',
      icon: Activity,
    },
    {
      id: 'threats',
      path: '/threats',
      aliases: ['/threat-detection'],
      label: 'Threats',
      desc: 'Alerts & classifications',
      icon: AlertTriangle,
    },
    {
      id: 'incidents',
      path: '/incidents',
      label: 'Incidents',
      desc: 'Correlated investigations',
      icon: FolderKanban,
    },
    {
      id: 'network',
      path: '/network',
      aliases: ['/network-layer2', '/internal-network', '/analytics'],
      label: 'Network',
      desc: 'Devices, IPs & connections',
      icon: Network,
    },
    {
      id: 'reports',
      path: '/reports',
      label: 'Reports',
      desc: 'Historical analysis',
      icon: FileText,
    },
  ];

  // Section 2: Administrator & Central Management (Sensors, system health, users & configurations)
  const adminNavItems = [
    {
      id: 'sensors',
      path: '/sensors',
      aliases: ['/management'],
      label: 'Sensors',
      desc: 'Monitoring status & health',
      icon: Radio,
    },
    {
      id: 'rules',
      path: '/rules',
      label: 'Rules',
      desc: 'Detection configuration',
      icon: Sliders,
    },
    {
      id: 'settings',
      path: '/settings',
      aliases: ['/users'],
      label: 'Settings',
      desc: 'Users, roles & org settings',
      icon: SettingsIcon,
    },
  ];

  const isCurrentActive = (item) => {
    if (location.pathname === item.path) return true;
    if (item.aliases && item.aliases.includes(location.pathname)) return true;
    return false;
  };

  return (
    <aside className="w-64 bg-gradient-to-b from-[#021338] via-[#041a4a] to-[#010e2b] flex flex-col justify-between select-none shrink-0 text-white z-20 relative overflow-hidden border-r border-[#0a2761]">
      {/* Ambient background waves */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden select-none">
        <div
          className="absolute -bottom-16 -left-16 w-80 h-80 rounded-full pointer-events-none blur-3xl opacity-40"
          style={{
            background: 'radial-gradient(circle, #0284c7 0%, #0369a1 40%, transparent 70%)',
          }}
        />
        <div
          className="absolute top-1/2 -left-20 w-72 h-72 rounded-full pointer-events-none blur-3xl opacity-25"
          style={{
            background: 'radial-gradient(circle, #1e40af 0%, #0c4a6e 50%, transparent 75%)',
          }}
        />
      </div>

      {/* Top Branding & Nav Items */}
      <div className="relative z-10 flex-1 overflow-y-auto pr-1">
        {/* Brand Header */}
        <div className="p-5 pb-4 flex items-center justify-between border-b border-blue-900/30">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#020b24] border border-cyan-400/40 p-1 flex items-center justify-center shadow-lg shadow-cyan-500/25 shrink-0 overflow-hidden group">
              <img
                src="/logo.jpeg"
                alt="NetrIQ Logo"
                className="w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(56,189,248,0.6)] group-hover:scale-105 transition-transform"
              />
            </div>
            <div>
              <div className="font-extrabold text-xl text-white tracking-tight">NetrIQ</div>
              <div className="text-[10px] font-mono text-cyan-400/80 uppercase">Enterprise NIDS</div>
            </div>
          </div>

          {/* User Persona Badge */}
          <div className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950/80 border border-blue-700/50 text-cyan-300">
            {role === 'admin' ? 'Admin' : 'Analyst'}
          </div>
        </div>

        {/* SECTION 1: INVESTIGATIONS / OPERATIONS (Visible to both Analyst & Admin) */}
        <div className="px-3 pt-4">
          <div className="px-2 pb-1.5 flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-cyan-400/80">
              {role === 'admin' ? 'Security Operations' : 'Investigations'}
            </span>
            <span className="text-[9px] font-sans text-slate-400">
              {role === 'admin' ? 'Threat Telemetry' : 'SOC Operations'}
            </span>
          </div>

          <div className="space-y-1">
            {analystNavItems.map((item) => {
              const active = isCurrentActive(item);
              const Icon = item.icon;

              return (
                <button
                  key={item.id}
                  onClick={() => navigate(item.path)}
                  className={`w-full text-left px-3 py-2 rounded-xl flex items-center gap-3 transition-all cursor-pointer text-xs ${
                    active
                      ? 'bg-[#1872eb] text-white font-semibold shadow-md shadow-blue-600/30'
                      : 'text-slate-300 hover:text-white hover:bg-white/[0.06]'
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 transition-colors ${
                      active ? 'text-white' : 'text-slate-400 group-hover:text-white'
                    }`}
                  />
                  <div className="truncate">
                    <div className="leading-tight font-medium text-xs">{item.label}</div>
                    <div className={`text-[10px] truncate ${active ? 'text-blue-100' : 'text-slate-400'}`}>
                      {item.desc}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* SECTION 2: ADMINISTRATOR (Only visible to Admin role) */}
        {role === 'admin' && (
          <div className="px-3 pt-5 pb-4">
            <div className="px-2 pb-1.5 flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-400/80">
                Administration
              </span>
              <span className="text-[9px] font-sans text-slate-400">Sensors & Platform</span>
            </div>

            <div className="space-y-1">
              {adminNavItems.map((item) => {
                const active = isCurrentActive(item);
                const Icon = item.icon;

                return (
                  <button
                    key={item.id}
                    onClick={() => navigate(item.path)}
                    className={`w-full text-left px-3 py-2 rounded-xl flex items-center gap-3 transition-all cursor-pointer text-xs ${
                      active
                        ? 'bg-[#1872eb] text-white font-semibold shadow-md shadow-blue-600/30'
                        : 'text-slate-300 hover:text-white hover:bg-white/[0.06]'
                    }`}
                  >
                    <Icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        active ? 'text-white' : 'text-slate-400 group-hover:text-white'
                      }`}
                    />
                    <div className="truncate">
                      <div className="leading-tight font-medium text-xs">{item.label}</div>
                      <div className={`text-[10px] truncate ${active ? 'text-blue-100' : 'text-slate-400'}`}>
                        {item.desc}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Bottom Status Card - Connected to live backend health */}
      <div className="p-3 relative z-10 border-t border-blue-900/40 bg-[#020b24]/60">
        <div className="bg-[#05235f]/80 backdrop-blur border border-[#0d3b8f] rounded-xl p-3 shadow-lg">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                systemHealth.status === 'healthy'
                  ? 'bg-[#10b981] shadow-emerald-400/50'
                  : 'bg-[#f59e0b] shadow-amber-400/50'
              } shadow-sm animate-pulse`}
            />
            <span className="text-xs font-semibold text-white">
              {systemHealth.status === 'healthy' ? 'System Online' : 'System Degraded'}
            </span>
          </div>
          <p className="text-[10px] text-slate-300 mt-0.5 truncate">
            {systemHealth.components?.live_monitor === 'running'
              ? 'NIDS packet engine inspecting live'
              : 'All core services operational'}
          </p>
        </div>

        <div className="mt-2 px-1 flex items-center justify-between text-[10px] text-slate-400 font-mono">
          <span>Last Poll</span>
          <span className="text-slate-300">{lastUpdated}</span>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
