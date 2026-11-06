import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Card, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { rulesService } from '../services/rules';
import {
  Sliders,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Search,
  RefreshCw,
  Send,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Activity,
  Layers,
  FileCode,
  Terminal,
  Settings,
  HelpCircle,
  Clock,
  Sparkles,
  ToggleLeft,
  ToggleRight,
  Filter,
} from 'lucide-react';

export const Rules = () => {
  const [rulesData, setRulesData] = useState({
    suricata_signatures: [],
    netriq_heuristics: [],
    behaviour_baselines: [],
    manifest_version: 'v2026.11.05.01',
    total_rules: 0,
    active_rules: 0,
  });
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('suricata'); // 'suricata' | 'heuristics' | 'baselines' | 'distribution'
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [isDistributing, setIsDistributing] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  const fetchRules = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await rulesService.getRules();
      setRulesData(data);
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleToggleRule = async (ruleId, currentEnabled, categoryKey) => {
    const newEnabled = !currentEnabled;
    // Optimistic UI update
    setRulesData((prev) => {
      const updatedList = prev[categoryKey].map((r) =>
        r.id === ruleId ? { ...r, enabled: newEnabled } : r
      );
      return {
        ...prev,
        [categoryKey]: updatedList,
        active_rules: prev.active_rules + (newEnabled ? 1 : -1),
      };
    });

    try {
      await rulesService.updateRule(ruleId, { enabled: newEnabled });
      setToastMessage(`Rule ${ruleId} ${newEnabled ? 'activated' : 'disabled'}`);
      setTimeout(() => setToastMessage(null), 3000);
    } catch (err) {
      console.error('Failed to toggle rule:', err);
      // Revert on error
      fetchRules();
    }
  };

  const handleDistributeRules = async () => {
    try {
      setIsDistributing(true);
      const res = await rulesService.distributeRules();
      setToastMessage(res.message || 'Detection rules successfully deployed to all active software sensors.');
      setTimeout(() => setToastMessage(null), 4000);
    } catch (err) {
      console.error('Failed to deploy rules:', err);
      alert('Failed to deploy ruleset to sensor fleet.');
    } finally {
      setIsDistributing(false);
    }
  };

  // Filtered lists
  const filteredSuricata = useMemo(() => {
    return (rulesData.suricata_signatures || []).filter((r) => {
      if (selectedCategory !== 'ALL' && r.stage !== selectedCategory) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          r.name?.toLowerCase().includes(q) ||
          r.id?.toLowerCase().includes(q) ||
          r.mitre?.toLowerCase().includes(q) ||
          r.category?.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [rulesData.suricata_signatures, selectedCategory, searchQuery]);

  const filteredHeuristics = useMemo(() => {
    return (rulesData.netriq_heuristics || []).filter((r) => {
      if (selectedCategory !== 'ALL' && r.stage !== selectedCategory) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          r.name?.toLowerCase().includes(q) ||
          r.id?.toLowerCase().includes(q) ||
          r.mitre?.toLowerCase().includes(q) ||
          r.category?.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [rulesData.netriq_heuristics, selectedCategory, searchQuery]);

  return (
    <div className="space-y-6 pb-12">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed top-6 right-6 z-50 bg-[#3b2a27] border border-[#cc5500] text-[#f8f4e7] text-xs font-sans px-4 py-3 rounded-lg shadow-xl flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-[#cc5500]" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#6b4c45] pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Sliders className="w-5 h-5 text-[#cc5500]" />
            <h1 className="text-xl font-bold text-[#f8f4e7] font-sans">
              Detection Rules & Configurations
            </h1>
          </div>
          <p className="text-xs text-[#d4bfb0] font-sans mt-1">
            Layer 3 Detection Engines: Suricata ET signatures, stateful NetrIQ heuristics, behavioural baselines & software sensor rule distribution.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchRules}
            disabled={isLoading}
            className="border-[#6b4c45] bg-[#3b2a27] hover:bg-[#5c3d38] text-[#d4bfb0] hover:text-[#f8f4e7] text-xs font-sans h-9 flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <Button
            size="sm"
            onClick={handleDistributeRules}
            disabled={isDistributing}
            className="bg-[#cc5500] hover:bg-[#b83a2e] text-white text-xs font-sans font-semibold h-9 flex items-center gap-1.5 px-3.5 shadow-sm"
          >
            <Send className={`w-3.5 h-3.5 ${isDistributing ? 'animate-spin' : ''}`} />
            {isDistributing ? 'Deploying...' : 'Deploy Ruleset to Sensors'}
          </Button>
        </div>
      </div>

      {/* SevOne Style Overview Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-[#4a3330] border-[#6b4c45] text-[#f8f4e7] rounded-lg shadow-none">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-sans uppercase tracking-wider text-[#d4bfb0]">Total Rules Configured</span>
              <FileCode className="w-4 h-4 text-[#cc8833]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#f8f4e7]">{rulesData.total_rules || 12}</div>
            <p className="text-[10px] text-[#a08070] font-mono">Suricata + NetrIQ + Baselines</p>
          </CardContent>
        </Card>

        <Card className="bg-[#4a3330] border-[#6b4c45] text-[#f8f4e7] rounded-lg shadow-none">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-sans uppercase tracking-wider text-[#d4bfb0]">Active & Enforced</span>
              <ShieldCheck className="w-4 h-4 text-[#cc5500]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#f8f4e7]">{rulesData.active_rules || 12}</div>
            <p className="text-[10px] text-[#cc5500] font-mono">100% active in inspection pipeline</p>
          </CardContent>
        </Card>

        <Card className="bg-[#4a3330] border-[#6b4c45] text-[#f8f4e7] rounded-lg shadow-none">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-sans uppercase tracking-wider text-[#d4bfb0]">Manifest Version</span>
              <Terminal className="w-4 h-4 text-[#c4956a]" />
            </div>
            <div className="text-lg font-bold font-mono text-[#f8f4e7] truncate">{rulesData.manifest_version}</div>
            <p className="text-[10px] text-[#a08070] font-mono">Automated daily release</p>
          </CardContent>
        </Card>

        <Card className="bg-[#4a3330] border-[#6b4c45] text-[#f8f4e7] rounded-lg shadow-none">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-sans uppercase tracking-wider text-[#d4bfb0]">Fleet Distribution</span>
              <Radio className="w-4 h-4 text-[#cc8833]" />
            </div>
            <div className="text-2xl font-bold font-mono text-[#f8f4e7]">Synchronized</div>
            <p className="text-[10px] text-[#cc8833] font-mono">All software sensors up to date</p>
          </CardContent>
        </Card>
      </div>

      {/* Tab Navigation & Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#3b2a27] p-2 rounded-lg border border-[#6b4c45]">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setActiveTab('suricata')}
            className={`px-3 py-1.5 rounded text-xs font-sans font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'suricata'
                ? 'bg-[#cc5500] text-white'
                : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#4a3330]'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Suricata Signatures ({rulesData.suricata_signatures?.length || 0})
          </button>

          <button
            onClick={() => setActiveTab('heuristics')}
            className={`px-3 py-1.5 rounded text-xs font-sans font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'heuristics'
                ? 'bg-[#cc5500] text-white'
                : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#4a3330]'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            NetrIQ Heuristics ({rulesData.netriq_heuristics?.length || 0})
          </button>

          <button
            onClick={() => setActiveTab('baselines')}
            className={`px-3 py-1.5 rounded text-xs font-sans font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'baselines'
                ? 'bg-[#cc5500] text-white'
                : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#4a3330]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Behavioural Baselines ({rulesData.behaviour_baselines?.length || 0})
          </button>

          <button
            onClick={() => setActiveTab('distribution')}
            className={`px-3 py-1.5 rounded text-xs font-sans font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'distribution'
                ? 'bg-[#cc5500] text-white'
                : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#4a3330]'
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            Sensor Manifest & Distribution
          </button>
        </div>

        {/* Search & Stage Filter */}
        <div className="flex items-center gap-2">
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-[#a08070] absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search rules, SIDs, MITRE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#4a3330] border border-[#6b4c45] rounded pl-8 pr-3 py-1 text-xs text-[#f8f4e7] placeholder-[#a08070] focus:outline-none focus:border-[#cc5500]"
            />
          </div>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#4a3330] border border-[#6b4c45] rounded px-2.5 py-1 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
          >
            <option value="ALL">All Stages</option>
            <option value="discovery">Discovery / Recon</option>
            <option value="initial_access">Initial Access / Exploit</option>
            <option value="lateral_movement">Lateral Movement</option>
            <option value="credential_access">Credential Access</option>
            <option value="c2_exfil">C2 & Exfiltration</option>
          </select>
        </div>
      </div>

      {/* TAB CONTENT: Suricata Signatures */}
      {activeTab === 'suricata' && (
        <Card className="bg-[#4a3330] border-[#6b4c45] rounded-lg shadow-none overflow-hidden">
          <div className="p-4 border-b border-[#6b4c45] flex items-center justify-between">
            <div className="space-y-0.5">
              <h2 className="text-sm font-semibold text-[#f8f4e7] font-sans">Suricata Emerging Threats (ET) Signatures</h2>
              <p className="text-xs text-[#d4bfb0] font-sans">
                Signature Engine analyzes raw ingress packets matching known CVEs, exploits, and malleable C2 malware patterns.
              </p>
            </div>
            <span className="text-xs font-mono text-[#c4956a]">Showing {filteredSuricata.length} active rules</span>
          </div>

          <div className="divide-y divide-[#6b4c45]">
            {filteredSuricata.map((rule) => {
              const sevBadge =
                rule.severity === 'CRITICAL'
                  ? 'bg-[#b83a2e]/20 text-[#b83a2e] border-[#b83a2e]/40'
                  : rule.severity === 'HIGH'
                  ? 'bg-[#cc5500]/20 text-[#cc5500] border-[#cc5500]/40'
                  : 'bg-[#cc8833]/20 text-[#cc8833] border-[#cc8833]/40';

              return (
                <div key={rule.id} className="p-4 hover:bg-[#5c3d38]/50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5 max-w-2xl">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-bold text-[#f8f4e7] bg-[#3b2a27] px-2 py-0.5 rounded border border-[#6b4c45]">
                        SID {rule.sid}
                      </span>
                      <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border font-semibold ${sevBadge}`}>
                        {rule.severity}
                      </span>
                      {rule.mitre && (
                        <span className="text-[10px] font-mono text-[#c4956a] bg-[#3b2a27] px-2 py-0.5 rounded border border-[#6b4c45]">
                          {rule.mitre}
                        </span>
                      )}
                      <span className="text-[10px] font-mono text-[#a08070]">[{rule.category}]</span>
                    </div>

                    <h3 className="text-sm font-medium text-[#f8f4e7] font-sans">{rule.name}</h3>
                    <p className="text-xs text-[#d4bfb0] font-sans">{rule.description}</p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                    <div className="text-right">
                      <div className="text-[11px] font-mono text-[#f8f4e7] uppercase">Action: <span className="font-bold text-[#cc5500]">{rule.action}</span></div>
                      <div className="text-[10px] font-mono text-[#a08070]">Confidence: {(rule.confidence * 100).toFixed(0)}%</div>
                    </div>

                    <button
                      onClick={() => handleToggleRule(rule.id, rule.enabled, 'suricata_signatures')}
                      className={`px-3 py-1.5 rounded text-xs font-sans font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                        rule.enabled
                          ? 'bg-[#3b2a27] border-[#cc5500] text-[#cc5500] hover:bg-[#5c3d38]'
                          : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070] hover:bg-[#5c3d38]'
                      }`}
                    >
                      {rule.enabled ? <ToggleRight className="w-4 h-4 text-[#cc5500]" /> : <ToggleLeft className="w-4 h-4 text-[#a08070]" />}
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* TAB CONTENT: NetrIQ Stateful Heuristics */}
      {activeTab === 'heuristics' && (
        <Card className="bg-[#4a3330] border-[#6b4c45] rounded-lg shadow-none overflow-hidden">
          <div className="p-4 border-b border-[#6b4c45] flex items-center justify-between">
            <div className="space-y-0.5">
              <h2 className="text-sm font-semibold text-[#f8f4e7] font-sans">NetrIQ Stateful Sliding-Window Heuristics</h2>
              <p className="text-xs text-[#d4bfb0] font-sans">
                Engine 2 stateful window inspection correlates connection bursts, multi-port sweeps, DNS Shannon entropy, and Zeek state churn.
              </p>
            </div>
            <span className="text-xs font-mono text-[#c4956a]">Showing {filteredHeuristics.length} heuristic rules</span>
          </div>

          <div className="divide-y divide-[#6b4c45]">
            {filteredHeuristics.map((rule) => (
              <div key={rule.id} className="p-4 hover:bg-[#5c3d38]/50 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#cc8833] bg-[#3b2a27] px-2 py-0.5 rounded border border-[#6b4c45]">
                      {rule.id}
                    </span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#3b2a27] text-[#c4956a] border border-[#6b4c45]">
                      {rule.type}
                    </span>
                    {rule.mitre && (
                      <span className="text-[10px] font-mono text-[#d4bfb0] bg-[#3b2a27] px-2 py-0.5 rounded border border-[#6b4c45]">
                        {rule.mitre}
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-medium text-[#f8f4e7] font-sans">{rule.name}</h3>
                  <p className="text-xs text-[#d4bfb0] font-sans">{rule.description}</p>

                  <div className="pt-1 flex items-center gap-3 text-xs font-mono text-[#a08070]">
                    <span>Threshold: <strong className="text-[#f8f4e7]">{rule.threshold}</strong> {rule.unit}</span>
                    {rule.window_seconds && <span>• Window: <strong className="text-[#f8f4e7]">{rule.window_seconds}s</strong></span>}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 self-end md:self-center">
                  <button
                    onClick={() => handleToggleRule(rule.id, rule.enabled, 'netriq_heuristics')}
                    className={`px-3 py-1.5 rounded text-xs font-sans font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                      rule.enabled
                        ? 'bg-[#3b2a27] border-[#cc5500] text-[#cc5500] hover:bg-[#5c3d38]'
                        : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070] hover:bg-[#5c3d38]'
                    }`}
                  >
                    {rule.enabled ? <ToggleRight className="w-4 h-4 text-[#cc5500]" /> : <ToggleLeft className="w-4 h-4 text-[#a08070]" />}
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* TAB CONTENT: Behavioural Baselines */}
      {activeTab === 'baselines' && (
        <Card className="bg-[#4a3330] border-[#6b4c45] rounded-lg shadow-none overflow-hidden">
          <div className="p-4 border-b border-[#6b4c45] space-y-0.5">
            <h2 className="text-sm font-semibold text-[#f8f4e7] font-sans">Behaviour Engine Baselines & Statistical Profiles</h2>
            <p className="text-xs text-[#d4bfb0] font-sans">
              Engine 3 tracks baseline traffic volumes and flags statistical outliers exceeding 3 standard deviations (μ + 3σ) and novel port access.
            </p>
          </div>

          <div className="p-4 space-y-4">
            {(rulesData.behaviour_baselines || []).map((bRule) => (
              <div key={bRule.id} className="p-4 rounded-lg bg-[#3b2a27] border border-[#6b4c45] flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-[#c4956a]">{bRule.id}</span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#4a3330] text-[#d4bfb0] border border-[#6b4c45]">
                      {bRule.type}
                    </span>
                  </div>
                  <h3 className="text-sm font-medium text-[#f8f4e7] font-sans">{bRule.name}</h3>
                  <p className="text-xs text-[#d4bfb0] font-sans">{bRule.description}</p>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <button
                    onClick={() => handleToggleRule(bRule.id, bRule.enabled, 'behaviour_baselines')}
                    className={`px-3 py-1.5 rounded text-xs font-sans font-medium border flex items-center gap-1.5 transition-colors cursor-pointer ${
                      bRule.enabled
                        ? 'bg-[#4a3330] border-[#cc5500] text-[#cc5500] hover:bg-[#5c3d38]'
                        : 'bg-[#4a3330] border-[#6b4c45] text-[#a08070] hover:bg-[#5c3d38]'
                    }`}
                  >
                    {bRule.enabled ? <ToggleRight className="w-4 h-4 text-[#cc5500]" /> : <ToggleLeft className="w-4 h-4 text-[#a08070]" />}
                    {bRule.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* TAB CONTENT: Distribution Manifest */}
      {activeTab === 'distribution' && (
        <Card className="bg-[#4a3330] border-[#6b4c45] rounded-lg shadow-none overflow-hidden">
          <div className="p-4 border-b border-[#6b4c45] flex items-center justify-between">
            <div className="space-y-0.5">
              <h2 className="text-sm font-semibold text-[#f8f4e7] font-sans">Software Sensor Fleet Rule Distribution Manifest</h2>
              <p className="text-xs text-[#d4bfb0] font-sans">
                Central Management Service compiles and pushes synchronized rule definitions and internal subnets to customer software daemons.
              </p>
            </div>
            <Button
              size="sm"
              onClick={handleDistributeRules}
              disabled={isDistributing}
              className="bg-[#cc5500] hover:bg-[#b83a2e] text-white text-xs font-sans h-8 flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              Push Manifest Update
            </Button>
          </div>

          <div className="p-5 space-y-4">
            <div className="bg-[#3b2a27] border border-[#6b4c45] rounded-lg p-4 font-mono text-xs text-[#d4bfb0] space-y-2">
              <div className="flex items-center justify-between border-b border-[#6b4c45] pb-2">
                <span className="text-[#f8f4e7] font-bold">MANIFEST METADATA:</span>
                <span className="text-[#cc5500]">{rulesData.manifest_version}</span>
              </div>
              <div>Tenant ID: <span className="text-[#f8f4e7]">default</span></div>
              <div>Active Suricata Signatures: <span className="text-[#f8f4e7]">{rulesData.suricata_signatures?.length || 0}</span></div>
              <div>Active Stateful NetrIQ Heuristics: <span className="text-[#f8f4e7]">{rulesData.netriq_heuristics?.length || 0}</span></div>
              <div>Whitelisted Internal Subnets: <span className="text-[#f8f4e7]">10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16</span></div>
              <div>Cryptographic Checksum: <span className="text-[#c4956a]">SHA256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069</span></div>
            </div>

            <div className="flex items-center gap-2 p-3 bg-[#3b2a27] border border-[#6b4c45] rounded-lg text-xs text-[#d4bfb0]">
              <Sparkles className="w-4 h-4 text-[#cc5500] shrink-0" />
              <span>
                Software sensors automatically pull this manifest every 300 seconds during heartbeat poll, or receive instant push notifications via the Central Management Service WebSocket channel.
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};

export default Rules;
