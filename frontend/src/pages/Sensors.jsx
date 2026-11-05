import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { managementService } from '../services/management';
import { useAuth } from '../context/AuthContext';
import {
  Cpu,
  Server,
  Activity,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Plus,
  Key,
  Layers,
  Copy,
  Check,
  X,
  FileCode,
  Radio,
  Sliders,
  Building,
  Terminal,
  ExternalLink,
  Info,
} from 'lucide-react';

export const Sensors = () => {
  const { user, role } = useAuth();
  const currentTenant = user?.tenant_id || 'default';

  const [sensors, setSensors] = useState([]);
  const [versionMatrix, setVersionMatrix] = useState(null);
  const [activeTab, setActiveTab] = useState('sensors'); // 'sensors' | 'rules' | 'versions' | 'organization'
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Modals state
  const [registerModalOpen, setRegisterModalOpen] = useState(false);
  const [registerForm, setRegisterForm] = useState({
    name: '',
    software_type: 'suricata',
    software_version: '7.0.2',
    hostname: 'cloud-edge-node01',
    listening_interface: 'eth0',
    environment: 'cloud_vm',
  });
  const [registrationResult, setRegistrationResult] = useState(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [isRegistering, setIsRegistering] = useState(false);

  // Config Update Modal state
  const [configModal, setConfigModal] = useState({
    open: false,
    sensorId: '',
    sensorName: '',
    interface: 'eth0',
    bufferSize: 256,
    logLevel: 'INFO',
    loading: false,
  });

  // Rule Manifest Viewer state
  const [rulesModal, setRulesModal] = useState({
    open: false,
    sensorId: '',
    manifest: null,
    loading: false,
  });

  // Load sensors and fleet telemetry
  const fetchFleet = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const [sensorList, matrix] = await Promise.all([
        managementService.getSensors(),
        managementService.getFleetVersionMatrix().catch(() => null),
      ]);
      setSensors(sensorList || []);
      setVersionMatrix(matrix);
    } catch (err) {
      console.error('Failed to fetch software sensor fleet:', err);
      setError('Unable to load software sensor fleet. Please check backend connection.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFleet();
  }, [fetchFleet]);

  // Register new software daemon
  const handleRegisterSensor = async (e) => {
    e.preventDefault();
    try {
      setIsRegistering(true);
      const payload = {
        tenant_id: currentTenant,
        name: registerForm.name,
        software_type: registerForm.software_type,
        software_version: registerForm.software_version,
        hostname: registerForm.hostname,
        listening_interface: registerForm.listening_interface,
        environment: registerForm.environment,
      };
      const result = await managementService.registerSensor(payload);
      setRegistrationResult(result);
      fetchFleet();
    } catch (err) {
      console.error('Registration error:', err);
      alert(err.response?.data?.detail || 'Failed to register software sensor.');
    } finally {
      setIsRegistering(false);
    }
  };

  // Copy API key to clipboard
  const handleCopyKey = () => {
    if (registrationResult?.api_key) {
      navigator.clipboard.writeText(registrationResult.api_key);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 3000);
    }
  };

  // Open config modal
  const handleOpenConfig = (sensor) => {
    setConfigModal({
      open: true,
      sensorId: sensor.sensor_id,
      sensorName: sensor.name,
      interface: sensor.listening_interface || 'eth0',
      bufferSize: sensor.config?.buffer_size_mb || 256,
      logLevel: sensor.config?.log_level || 'INFO',
      loading: false,
    });
  };

  // Save remote daemon config
  const handleSaveConfig = async () => {
    try {
      setConfigModal((prev) => ({ ...prev, loading: true }));
      await managementService.updateSensorConfig(configModal.sensorId, {
        listening_interface: configModal.interface,
        capture_buffer_size_mb: Number(configModal.bufferSize),
        log_level: configModal.logLevel,
      });
      setConfigModal({ open: false, sensorId: '', sensorName: '', interface: 'eth0', bufferSize: 256, logLevel: 'INFO', loading: false });
      fetchFleet();
    } catch (err) {
      console.error('Config update error:', err);
      alert(err.response?.data?.detail || 'Failed to update remote sensor config.');
      setConfigModal((prev) => ({ ...prev, loading: false }));
    }
  };

  // Open rule manifest drawer/modal
  const handleViewRules = async (sensorId) => {
    try {
      setRulesModal({ open: true, sensorId, manifest: null, loading: true });
      const manifest = await managementService.getSensorRules(sensorId);
      setRulesModal({ open: true, sensorId, manifest, loading: false });
    } catch (err) {
      console.error('Failed to load rule manifest:', err);
      alert('Failed to retrieve active rule manifest.');
      setRulesModal({ open: false, sensorId: '', manifest: null, loading: false });
    }
  };

  // Simulate heartbeat for a sensor daemon (testing health & kernel drops)
  const handleSimulateHeartbeat = async (sensorId) => {
    try {
      await managementService.sendHeartbeat(sensorId, {
        cpu_usage_pct: +(Math.random() * 40 + 10).toFixed(1),
        memory_usage_mb: +(Math.random() * 200 + 450).toFixed(1),
        kernel_drops_count: Math.floor(Math.random() * 20),
        packets_processed: Math.floor(Math.random() * 50000 + 10000),
        uptime_seconds: 3600 + Math.floor(Math.random() * 86400),
      });
      fetchFleet();
    } catch (err) {
      console.error('Heartbeat error:', err);
    }
  };

  // Compute fleet statistics
  const totalSensors = sensors.length;
  const onlineSensors = sensors.filter((s) => s.status === 'healthy').length;
  const totalKernelDrops = sensors.reduce((acc, s) => acc + (s.kernel_drops_count || 0), 0);
  const outdatedSensors = sensors.filter((s) => s.is_version_outdated).length;

  return (
    <div className="space-y-6 pb-12 font-sans text-[#E7ECEF]">
      {/* 1. Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#19242E] border border-[#2A3944] p-5 rounded-lg">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <h1 className="text-lg font-semibold tracking-normal text-[#E7ECEF] flex items-center gap-2 font-sans">
              <Radio className="w-5 h-5 text-[#cc5500]" />
              Software Sensor Fleet & Central Management
            </h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#cc5500]/15 text-[#cc5500] border border-[#cc5500]/30 uppercase">
              Tenant: {currentTenant}
            </span>
          </div>
          <p className="text-xs text-[#9AA8B2] font-sans">
            Central orchestration for distributed software daemons (Suricata, Zeek, NetrIQ Collector) running across customer VMs, cloud nodes, and containers.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchFleet}
            disabled={isLoading}
            className="text-xs border-[#2A3944] bg-[#101820] hover:bg-[#202D36] text-[#E7ECEF] flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh Fleet
          </Button>

          <button
            onClick={() => {
              setRegistrationResult(null);
              setRegisterModalOpen(true);
            }}
            className="text-xs bg-[#cc5500] hover:bg-[#b83a2e] text-[#f8f4e7] font-sans font-semibold h-8 px-3 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Software Sensor
          </button>
        </div>
      </div>

      {/* 2. Fleet Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Sensors */}
        <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-1">
          <span className="text-[11px] font-mono uppercase text-[#9AA8B2] flex items-center justify-between">
            Software Sensors
            <Cpu className="w-3.5 h-3.5 text-[#cc5500]" />
          </span>
          <div className="text-2xl font-bold font-mono text-[#E7ECEF]">
            {totalSensors} <span className="text-xs font-normal text-[#9AA8B2]">daemons</span>
          </div>
          <span className="text-xs text-[#9AA8B2]">Suricata, Zeek & Collectors</span>
        </div>

        {/* Online Status */}
        <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-1">
          <span className="text-[11px] font-mono uppercase text-[#9AA8B2] flex items-center justify-between">
            Daemon Health
            <Activity className="w-3.5 h-3.5 text-[#50C878]" />
          </span>
          <div className="text-2xl font-bold font-mono text-[#50C878]">
            {onlineSensors} / {totalSensors}
          </div>
          <span className="text-xs text-[#9AA8B2]">Active heartbeats &lt; 60s</span>
        </div>

        {/* Kernel Packet Drops */}
        <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-1">
          <span className="text-[11px] font-mono uppercase text-[#9AA8B2] flex items-center justify-between">
            Kernel Packet Loss
            <AlertTriangle className="w-3.5 h-3.5 text-[#DF857C]" />
          </span>
          <div className="text-2xl font-bold font-mono text-[#E7ECEF]">
            {totalKernelDrops.toLocaleString()} <span className="text-xs font-normal text-[#9AA8B2]">drops</span>
          </div>
          <span className="text-xs text-[#9AA8B2]">Ring buffer saturation telemetry</span>
        </div>

        {/* Outdated Software */}
        <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-1">
          <span className="text-[11px] font-mono uppercase text-[#9AA8B2] flex items-center justify-between">
            Software Compliance
            <Layers className="w-3.5 h-3.5 text-[#D3A35D]" />
          </span>
          <div className="text-2xl font-bold font-mono text-[#E7ECEF]">
            {outdatedSensors === 0 ? (
              <span className="text-[#50C878]">100% Current</span>
            ) : (
              <span className="text-[#D3A35D]">{outdatedSensors} Outdated</span>
            )}
          </div>
          <span className="text-xs text-[#9AA8B2]">Benchmarks: Suricata 7.0.2, Zeek 6.0.3</span>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-[#2A3944] pb-2 text-xs font-sans">
        <button
          onClick={() => setActiveTab('sensors')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
            activeTab === 'sensors'
              ? 'bg-[#202D36] text-[#E7ECEF] border border-[#2A3944]'
              : 'text-[#9AA8B2] hover:text-[#E7ECEF]'
          }`}
        >
          Software Sensors ({sensors.length})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
            activeTab === 'rules'
              ? 'bg-[#202D36] text-[#E7ECEF] border border-[#2A3944]'
              : 'text-[#9AA8B2] hover:text-[#E7ECEF]'
          }`}
        >
          Rule Distribution
        </button>
        <button
          onClick={() => setActiveTab('versions')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
            activeTab === 'versions'
              ? 'bg-[#202D36] text-[#E7ECEF] border border-[#2A3944]'
              : 'text-[#9AA8B2] hover:text-[#E7ECEF]'
          }`}
        >
          Version Matrix
        </button>
        <button
          onClick={() => setActiveTab('organization')}
          className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
            activeTab === 'organization'
              ? 'bg-[#202D36] text-[#E7ECEF] border border-[#2A3944]'
              : 'text-[#9AA8B2] hover:text-[#E7ECEF]'
          }`}
        >
          Tenant & Organisation Profile
        </button>
      </div>

      {/* 4. Tab Contents */}

      {/* TAB A: SOFTWARE SENSORS TABLE */}
      {activeTab === 'sensors' && (
        <Card className="bg-[#19242E] border border-[#2A3944] shadow-none rounded-lg overflow-hidden">
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-12 text-center text-[#9AA8B2]">
                <div className="w-7 h-7 border-2 border-[#2A3944] border-t-[#cc5500] rounded-full animate-spin mx-auto mb-2" />
                <span>Polling software sensor daemon telemetry...</span>
              </div>
            ) : sensors.length === 0 ? (
              <div className="p-12 text-center space-y-3">
                <Radio className="w-8 h-8 text-[#9AA8B2] mx-auto opacity-40" />
                <h4 className="text-sm font-semibold text-[#E7ECEF]">No Software Sensors Registered</h4>
                <p className="text-xs text-[#9AA8B2] max-w-md mx-auto">
                  Deploy NetrIQ software sensor daemons (Suricata, Zeek, or Collector) onto your virtual machines, cloud instances, or Kubernetes clusters.
                </p>
                <button
                  onClick={() => setRegisterModalOpen(true)}
                  className="mt-2 text-xs bg-[#cc5500] hover:bg-[#b83a2e] text-[#f8f4e7] px-3.5 py-1.5 rounded-lg font-semibold inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Provision First Software Sensor
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-[#101820] text-[#9AA8B2] uppercase font-mono text-[10px] border-b border-[#2A3944]">
                    <tr>
                      <th className="py-3 px-4">Sensor / Daemon</th>
                      <th className="py-3 px-4">Software Type</th>
                      <th className="py-3 px-4">Host / Environment</th>
                      <th className="py-3 px-4">Interface</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Health Telemetry</th>
                      <th className="py-3 px-4">Software Version</th>
                      <th className="py-3 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#2A3944]/60 font-sans">
                    {sensors.map((sensor) => {
                      const isHealthy = sensor.status === 'healthy';
                      const isDegraded = sensor.status === 'degraded';

                      return (
                        <tr key={sensor.sensor_id} className="hover:bg-[#202D36]/40 transition-colors">
                          {/* Name & ID */}
                          <td className="py-3.5 px-4">
                            <div className="font-semibold text-[#E7ECEF] flex items-center gap-1.5">
                              <Radio className="w-3.5 h-3.5 text-[#cc5500]" />
                              {sensor.name}
                            </div>
                            <div className="text-[11px] font-mono text-[#9AA8B2]">{sensor.sensor_id}</div>
                          </td>

                          {/* Software Type */}
                          <td className="py-3.5 px-4 font-mono">
                            <span className="px-2 py-0.5 rounded bg-[#101820] text-[#E7ECEF] border border-[#2A3944] uppercase text-[10px]">
                              {sensor.software_type}
                            </span>
                          </td>

                          {/* Hostname & Env */}
                          <td className="py-3.5 px-4">
                            <div className="font-mono text-[#E7ECEF]">{sensor.hostname}</div>
                            <div className="text-[10px] text-[#9AA8B2] uppercase font-mono">{sensor.environment}</div>
                          </td>

                          {/* Listening Interface */}
                          <td className="py-3.5 px-4 font-mono text-[#E7ECEF]">
                            {sensor.listening_interface || 'eth0'}
                          </td>

                          {/* Status */}
                          <td className="py-3.5 px-4">
                            <span
                              className={`inline-flex items-center gap-1 text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${
                                isHealthy
                                  ? 'bg-[#50C878]/15 text-[#50C878] border-[#50C878]/30'
                                  : isDegraded
                                  ? 'bg-[#D3A35D]/15 text-[#D3A35D] border-[#D3A35D]/30'
                                  : 'bg-[#DF857C]/15 text-[#DF857C] border-[#DF857C]/30'
                              }`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${isHealthy ? 'bg-[#50C878]' : isDegraded ? 'bg-[#D3A35D]' : 'bg-[#DF857C]'}`} />
                              {sensor.status}
                            </span>
                          </td>

                          {/* Health Metrics */}
                          <td className="py-3.5 px-4 font-mono text-[11px]">
                            <div className="text-[#E7ECEF]">
                              CPU: {sensor.cpu_usage_pct}% • RAM: {Math.round(sensor.memory_usage_mb)} MB
                            </div>
                            <div className="text-[10px] text-[#9AA8B2]">
                              Drops: <strong className={sensor.kernel_drops_count > 0 ? 'text-[#DF857C]' : 'text-[#50C878]'}>{sensor.kernel_drops_count}</strong> pkts • Pkts: {sensor.packets_processed.toLocaleString()}
                            </div>
                          </td>

                          {/* Software Version */}
                          <td className="py-3.5 px-4 font-mono text-xs">
                            <span className="text-[#E7ECEF]">{sensor.software_version}</span>
                            {sensor.is_version_outdated ? (
                              <span className="block text-[10px] text-[#D3A35D]">Update recommended</span>
                            ) : (
                              <span className="block text-[10px] text-[#50C878]">Up to date</span>
                            )}
                          </td>

                          {/* Actions */}
                          <td className="py-3.5 px-4 text-right space-x-1.5">
                            <button
                              onClick={() => handleViewRules(sensor.sensor_id)}
                              className="px-2 py-1 rounded bg-[#101820] hover:bg-[#202D36] border border-[#2A3944] text-[#E7ECEF] text-[11px] font-medium cursor-pointer"
                              title="Inspect distributed rules"
                            >
                              Rules
                            </button>
                            <button
                              onClick={() => handleOpenConfig(sensor)}
                              className="px-2 py-1 rounded bg-[#101820] hover:bg-[#202D36] border border-[#2A3944] text-[#E7ECEF] text-[11px] font-medium cursor-pointer"
                              title="Tuning & buffer configuration"
                            >
                              Configure
                            </button>
                            <button
                              onClick={() => handleSimulateHeartbeat(sensor.sensor_id)}
                              className="px-2 py-1 rounded bg-[#101820] hover:bg-[#202D36] border border-[#2A3944] text-[#9AA8B2] hover:text-[#E7ECEF] text-[11px] cursor-pointer"
                              title="Test heartbeat"
                            >
                              Ping
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* TAB B: RULE DISTRIBUTION */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="bg-[#19242E] border border-[#2A3944] p-5 rounded-lg space-y-2">
            <h3 className="text-sm font-semibold text-[#E7ECEF] flex items-center gap-2">
              <FileCode className="w-4 h-4 text-[#cc5500]" />
              Distributed Detection Rule Manifests
            </h3>
            <p className="text-xs text-[#9AA8B2]">
              Central Management compiles and pushes rule manifests to distributed software sensors. Sensors query their active manifest via authenticated REST polling.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Suricata Rules Manifest */}
            <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#2A3944]">
                <span className="font-semibold text-xs text-[#E7ECEF]">Suricata ET Signatures Manifest</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#101820] text-[#cc5500] border border-[#2A3944]">Active Ruleset</span>
              </div>
              <div className="space-y-2 font-mono text-xs">
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#50C878]">alert tcp any any -&gt; any 445 (msg:"ET EXPLOIT Lateral SMB Exec")</div>
                  <div className="text-[10px] text-[#9AA8B2] mt-0.5">SID: 2010935 • Classtype: attempted-admin</div>
                </div>
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#50C878]">alert tcp any any -&gt; any 443 (msg:"ET TROJAN Cobalt Strike Beaconing")</div>
                  <div className="text-[10px] text-[#9AA8B2] mt-0.5">SID: 2028911 • Classtype: trojan-activity</div>
                </div>
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#50C878]">alert tcp any any -&gt; any any (msg:"ET SCAN Potential Nmap Service Sweep")</div>
                  <div className="text-[10px] text-[#9AA8B2] mt-0.5">SID: 2001219 • Classtype: network-scan</div>
                </div>
              </div>
            </div>

            {/* NetrIQ Stateful Rules */}
            <div className="p-4 rounded-lg bg-[#19242E] border border-[#2A3944] space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-[#2A3944]">
                <span className="font-semibold text-xs text-[#E7ECEF]">NetrIQ Threshold &amp; Stateful Rules</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#101820] text-[#cc5500] border border-[#2A3944]">Sliding Windows</span>
              </div>
              <div className="space-y-2 font-mono text-xs">
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#E7ECEF] font-semibold">NETRIQ:RULE:PORT_SCAN_RECON</div>
                  <div className="text-[11px] text-[#9AA8B2]">Threshold: &ge; 8 unique destination ports within 60s sliding window</div>
                </div>
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#E7ECEF] font-semibold">NETRIQ:RULE:FAILED_CONNECTION_CHURN</div>
                  <div className="text-[11px] text-[#9AA8B2]">Threshold: &ge; 5 failed connection states (S0, REJ) within 60s</div>
                </div>
                <div className="p-2.5 rounded bg-[#101820] border border-[#2A3944]/60">
                  <div className="text-[#E7ECEF] font-semibold">NETRIQ:RULE:UNUSUAL_DNS_ACTIVITY</div>
                  <div className="text-[11px] text-[#9AA8B2]">Shannon Entropy: &ge; 3.8 and query length &ge; 35 characters</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB C: VERSION MATRIX */}
      {activeTab === 'versions' && (
        <Card className="bg-[#19242E] border border-[#2A3944] shadow-none rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#2A3944]">
            <div>
              <h3 className="text-sm font-semibold text-[#E7ECEF]">Software Sensor Daemon Release Audit</h3>
              <p className="text-xs text-[#9AA8B2]">
                Verifies that customer-deployed Suricata, Zeek, and NetrIQ software daemons match target baseline releases.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-[#101820] border border-[#2A3944] space-y-1">
              <span className="text-[10px] font-mono uppercase text-[#9AA8B2]">Suricata Benchmark</span>
              <div className="text-xl font-bold font-mono text-[#50C878]">v7.0.2</div>
              <span className="text-[11px] text-[#9AA8B2]">Official stable multi-threaded NIDS release</span>
            </div>
            <div className="p-4 rounded-lg bg-[#101820] border border-[#2A3944] space-y-1">
              <span className="text-[10px] font-mono uppercase text-[#9AA8B2]">Zeek Benchmark</span>
              <div className="text-xl font-bold font-mono text-[#50C878]">v6.0.3</div>
              <span className="text-[11px] text-[#9AA8B2]">LTS network analysis framework</span>
            </div>
            <div className="p-4 rounded-lg bg-[#101820] border border-[#2A3944] space-y-1">
              <span className="text-[10px] font-mono uppercase text-[#9AA8B2]">NetrIQ Collector Benchmark</span>
              <div className="text-xl font-bold font-mono text-[#50C878]">v1.2.0</div>
              <span className="text-[11px] text-[#9AA8B2]">NCEF normalization daemon</span>
            </div>
          </div>

          {versionMatrix && versionMatrix.fleet && (
            <div className="overflow-x-auto pt-2">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-[#101820] text-[#9AA8B2] uppercase font-mono text-[10px] border-b border-[#2A3944]">
                  <tr>
                    <th className="py-2.5 px-4">Daemon</th>
                    <th className="py-2.5 px-4">Software Type</th>
                    <th className="py-2.5 px-4">Installed Version</th>
                    <th className="py-2.5 px-4">Target Benchmark</th>
                    <th className="py-2.5 px-4">Compliance Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2A3944]/50 font-mono text-xs">
                  {versionMatrix.fleet.map((item) => (
                    <tr key={item.sensor_id}>
                      <td className="py-2.5 px-4 text-[#E7ECEF] font-sans font-semibold">{item.name}</td>
                      <td className="py-2.5 px-4 uppercase">{item.software_type}</td>
                      <td className="py-2.5 px-4">{item.installed_version}</td>
                      <td className="py-2.5 px-4 text-[#50C878]">{item.benchmark_version}</td>
                      <td className="py-2.5 px-4">
                        {item.is_outdated ? (
                          <span className="text-[#D3A35D]">Upgrade Required</span>
                        ) : (
                          <span className="text-[#50C878]">Compliant</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {/* TAB D: ORGANISATION PROFILE & TENANT ISOLATION */}
      {activeTab === 'organization' && (
        <Card className="bg-[#19242E] border border-[#2A3944] shadow-none rounded-lg p-5 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-[#2A3944]">
            <div>
              <h3 className="text-sm font-semibold text-[#E7ECEF] flex items-center gap-2">
                <Building className="w-4 h-4 text-[#cc5500]" />
                Customer Deployment & Tenant Isolation
              </h3>
              <p className="text-xs text-[#9AA8B2]">
                NetrIQ enforces strict multi-tenant boundaries. A customer organisation only has access to their own software sensors and incident investigations.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
            <div className="p-4 rounded-lg bg-[#101820] border border-[#2A3944] space-y-2">
              <span className="text-[11px] font-mono uppercase text-[#9AA8B2]">Tenant Identifier</span>
              <div className="font-mono text-base font-bold text-[#E7ECEF]">{currentTenant}</div>
              <div className="text-[11px] text-[#9AA8B2]">All sensor logs and incident queries are partitioned by this key.</div>
            </div>

            <div className="p-4 rounded-lg bg-[#101820] border border-[#2A3944] space-y-2">
              <span className="text-[11px] font-mono uppercase text-[#9AA8B2]">Monitored Internal Subnets</span>
              <div className="font-mono text-xs text-[#50C878] space-y-0.5">
                <div>10.0.0.0/8 (Corporate Internal Subnet)</div>
                <div>172.16.0.0/12 (DMZ Services)</div>
                <div>192.168.0.0/16 (Workstations &amp; Wi-Fi)</div>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* ========================================================= */}
      {/* MODALS */}
      {/* ========================================================= */}

      {/* 1. Register Software Sensor Modal */}
      {registerModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#19242E] border border-[#2A3944] rounded-xl max-w-lg w-full p-6 space-y-5 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3 border-b border-[#2A3944]">
              <h3 className="text-sm font-bold text-[#E7ECEF] font-sans flex items-center gap-2">
                <Radio className="w-4 h-4 text-[#cc5500]" />
                Register Software Sensor Daemon
              </h3>
              <button
                onClick={() => setRegisterModalOpen(false)}
                className="text-[#9AA8B2] hover:text-[#E7ECEF]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {registrationResult ? (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-[#50C878]/10 border border-[#50C878]/30 text-xs space-y-2">
                  <div className="font-bold text-[#50C878] flex items-center gap-1.5">
                    <Check className="w-4 h-4" />
                    Software Sensor Successfully Provisioned!
                  </div>
                  <p className="text-[#9AA8B2]">
                    Sensor ID: <strong className="font-mono text-[#E7ECEF]">{registrationResult.sensor_id}</strong>
                  </p>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-mono text-[#9AA8B2]">
                    Generated Software API Key (One-Time Display)
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      readOnly
                      value={registrationResult.api_key}
                      className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 font-mono text-xs text-[#50C878] select-all"
                    />
                    <button
                      onClick={handleCopyKey}
                      className="px-3 py-2.5 rounded-lg bg-[#202D36] hover:bg-[#2A3944] text-[#E7ECEF] text-xs flex items-center gap-1 border border-[#2A3944] cursor-pointer"
                    >
                      {copiedKey ? <Check className="w-4 h-4 text-[#50C878]" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#101820] border border-[#2A3944] text-xs font-mono text-[#9AA8B2] space-y-1">
                  <div className="text-[#cc5500] font-semibold">Daemon Ingestion Header Instruction:</div>
                  <div>Pass <code className="text-[#E7ECEF]">X-Sensor-Key: {registrationResult.api_key.slice(0, 14)}...</code> on all HTTP requests.</div>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    onClick={() => {
                      setRegistrationResult(null);
                      setRegisterModalOpen(false);
                    }}
                    className="px-4 py-2 bg-[#cc5500] hover:bg-[#b83a2e] text-[#f8f4e7] rounded-lg text-xs font-semibold cursor-pointer"
                  >
                    Done
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleRegisterSensor} className="space-y-3.5 text-xs font-sans">
                <div>
                  <label className="block text-[#9AA8B2] font-mono mb-1">Software Daemon Type</label>
                  <select
                    value={registerForm.software_type}
                    onChange={(e) => setRegisterForm({ ...registerForm, software_type: e.target.value })}
                    className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                  >
                    <option value="suricata">Suricata Daemon (EVE Alert Engine)</option>
                    <option value="zeek">Zeek Network Monitor Daemon (Conn / DNS)</option>
                    <option value="netriq_collector">NetrIQ Ingestion Collector (NCEF)</option>
                    <option value="endpoint_agent">Endpoint Agent Daemon</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#9AA8B2] font-mono mb-1">Sensor Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. suricata-edge-dc1"
                    value={registerForm.name}
                    onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
                    className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[#9AA8B2] font-mono mb-1">Hostname / Container</label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. k8s-pod-zeek01"
                      value={registerForm.hostname}
                      onChange={(e) => setRegisterForm({ ...registerForm, hostname: e.target.value })}
                      className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                    />
                  </div>
                  <div>
                    <label className="block text-[#9AA8B2] font-mono mb-1">Listening Interface</label>
                    <input
                      type="text"
                      placeholder="e.g. eth0, mirror0"
                      value={registerForm.listening_interface}
                      onChange={(e) => setRegisterForm({ ...registerForm, listening_interface: e.target.value })}
                      className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[#9AA8B2] font-mono mb-1">Deployment Environment</label>
                    <select
                      value={registerForm.environment}
                      onChange={(e) => setRegisterForm({ ...registerForm, environment: e.target.value })}
                      className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                    >
                      <option value="cloud_vm">Cloud Virtual Machine (AWS/GCP/Azure)</option>
                      <option value="container">Docker / Kubernetes Container</option>
                      <option value="on_prem_vm">On-Premises VM (ESXi / Proxmox)</option>
                      <option value="bare_metal">Bare Metal Linux Server</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[#9AA8B2] font-mono mb-1">Installed Version</label>
                    <input
                      type="text"
                      placeholder="e.g. 7.0.2"
                      value={registerForm.software_version}
                      onChange={(e) => setRegisterForm({ ...registerForm, software_version: e.target.value })}
                      className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#2A3944]">
                  <button
                    type="button"
                    onClick={() => setRegisterModalOpen(false)}
                    className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#9AA8B2] hover:text-[#E7ECEF] bg-[#101820] hover:bg-[#202D36] border border-[#2A3944] cursor-pointer"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={isRegistering}
                    className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
                  >
                    {isRegistering ? 'Provisioning...' : 'Provision Software Sensor'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* 2. Configure Sensor Modal */}
      {configModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#19242E] border border-[#2A3944] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#2A3944]">
              <h3 className="text-sm font-bold text-[#E7ECEF] font-sans flex items-center gap-2">
                <Sliders className="w-4 h-4 text-[#cc5500]" />
                Configure Daemon ({configModal.sensorName})
              </h3>
              <button
                onClick={() => setConfigModal({ ...configModal, open: false })}
                className="text-[#9AA8B2] hover:text-[#E7ECEF]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-sans">
              <div>
                <label className="block text-[#9AA8B2] font-mono mb-1">Listening Network Interface</label>
                <input
                  type="text"
                  value={configModal.interface}
                  onChange={(e) => setConfigModal({ ...configModal, interface: e.target.value })}
                  className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                />
              </div>

              <div>
                <label className="block text-[#9AA8B2] font-mono mb-1">Capture Buffer Size (MB)</label>
                <input
                  type="number"
                  value={configModal.bufferSize}
                  onChange={(e) => setConfigModal({ ...configModal, bufferSize: e.target.value })}
                  className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                />
              </div>

              <div>
                <label className="block text-[#9AA8B2] font-mono mb-1">Logging Level</label>
                <select
                  value={configModal.logLevel}
                  onChange={(e) => setConfigModal({ ...configModal, logLevel: e.target.value })}
                  className="w-full bg-[#101820] border border-[#2A3944] rounded-lg p-2.5 text-[#E7ECEF] focus:outline-none focus:border-[#cc5500]"
                >
                  <option value="DEBUG">DEBUG</option>
                  <option value="INFO">INFO</option>
                  <option value="WARN">WARN</option>
                  <option value="ERROR">ERROR</option>
                </select>
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setConfigModal({ ...configModal, open: false })}
                className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#9AA8B2] hover:text-[#E7ECEF] bg-[#101820] hover:bg-[#202D36] border border-[#2A3944] cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveConfig}
                disabled={configModal.loading}
                className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
              >
                {configModal.loading ? 'Pushing Config...' : 'Push Configuration'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 3. Rule Manifest Drawer/Modal */}
      {rulesModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#19242E] border border-[#2A3944] rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#2A3944]">
              <h3 className="text-sm font-bold text-[#E7ECEF] font-sans flex items-center gap-2">
                <FileCode className="w-4 h-4 text-[#cc5500]" />
                Rule Manifest ({rulesModal.sensorId})
              </h3>
              <button
                onClick={() => setRulesModal({ open: false, sensorId: '', manifest: null, loading: false })}
                className="text-[#9AA8B2] hover:text-[#E7ECEF]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {rulesModal.loading ? (
              <div className="p-8 text-center text-xs text-[#9AA8B2]">Loading manifest from Central Management...</div>
            ) : rulesModal.manifest ? (
              <div className="space-y-3 text-xs font-mono">
                <div className="text-[11px] text-[#9AA8B2]">
                  Manifest Version: <strong className="text-[#E7ECEF]">{rulesModal.manifest.version}</strong> • Distributed to software sensor.
                </div>
                <div className="max-h-64 overflow-y-auto space-y-2 pr-1">
                  {rulesModal.manifest.suricata_rules?.map((r, i) => (
                    <div key={i} className="p-2 rounded bg-[#101820] border border-[#2A3944] text-[11px]">
                      <span className="text-[#50C878] font-semibold">{r.msg}</span>
                      <span className="block text-[10px] text-[#9AA8B2]">SID: {r.sid} • Classtype: {r.classtype}</span>
                    </div>
                  ))}
                  {rulesModal.manifest.netriq_rules?.map((r, i) => (
                    <div key={i} className="p-2 rounded bg-[#101820] border border-[#2A3944] text-[11px]">
                      <span className="text-[#E7ECEF] font-semibold">{r.rule_id}</span>
                      <span className="block text-[10px] text-[#9AA8B2]">Type: {r.type}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-[#9AA8B2]">No active manifest found.</div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setRulesModal({ open: false, sensorId: '', manifest: null, loading: false })}
                className="px-3.5 py-1.5 rounded-lg text-xs bg-[#202D36] text-[#E7ECEF] hover:bg-[#2A3944] border border-[#2A3944] cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Sensors;

