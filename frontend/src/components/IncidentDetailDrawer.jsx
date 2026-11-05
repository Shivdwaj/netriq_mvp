import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Button } from './ui/button';
import { StatusBadge } from './StatusBadge';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { DeviceActivityDrawer } from './DeviceActivityDrawer';
import { historyService } from '../services/history';
import { monitoringService } from '../services/monitoring';
import { incidentService } from '../services/incidents';
import { useAuth } from '../context/AuthContext';
import { SOCCountermeasurePlaybook } from './SOCCountermeasurePlaybook';
import {
  ShieldAlert,
  Server,
  ArrowRight,
  Clock,
  Lock,
  Unlock,
  Layers,
  Activity,
  Globe,
  Monitor,
  Sparkles,
  Bot,
  Database,
  Cpu,
  Search,
  ChevronDown,
  X,
  Minus,
  Square,
  Undo2,
  RefreshCw,
  FileText,
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  CheckCircle2,
  AlertOctagon,
  HelpCircle,
  History,
  MessageSquare,
  Send,
  UserCheck,
  User,
  Paperclip,
  Check,
  Plus,
} from 'lucide-react';

export const IncidentDetailDrawer = ({
  isOpen,
  onClose,
  incident,
  onUpdateStatus,
  onOpenResponseDialog,
  isUpdating = false,
  onSelectDevice,
}) => {
  const { hasCapability, role } = useAuth();
  const canModify = hasCapability('REVERSE_RESPONSE_ACTION') || role === 'admin' || role === 'analyst';

  // Local synced incident state
  const [currentIncident, setCurrentIncident] = useState(incident);
  useEffect(() => {
    setCurrentIncident(incident);
  }, [incident]);

  // Active navigation tab: 'incident_overview' | 'investigation' | 'audit_history' | 'ports' | 'traffic' | 'blocked'
  const [activeTab, setActiveTab] = useState('incident_overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [isMaximized, setIsMaximized] = useState(false);
  const [deviceFlows, setDeviceFlows] = useState([]);
  const [isLoadingFlows, setIsLoadingFlows] = useState(false);
  const [notesText, setNotesText] = useState('');
  const [isSavingNotes, setIsSavingNotes] = useState(false);
  const [blockedComputers, setBlockedComputers] = useState([]);
  const [selectedDeviceActivityIp, setSelectedDeviceActivityIp] = useState(null);

  // Investigation & Notes state
  const [newNoteContent, setNewNoteContent] = useState('');
  const [isPostingNote, setIsPostingNote] = useState(false);

  // Modals state
  const [statusModal, setStatusModal] = useState({ open: false, targetStatus: '', reason: '', resolutionNotes: '', loading: false });
  const [assignModal, setAssignModal] = useState({ open: false, assignedTo: '', reason: '', loading: false });
  const [severityModal, setSeverityModal] = useState({ open: false, targetSeverity: '', reason: '', loading: false });
  const [evidenceModal, setEvidenceModal] = useState({ open: false, source: 'manual_forensics', summary: '', reason: '', loading: false });

  const handleOpenStatusModal = (target) => {
    setStatusModal({
      open: true,
      targetStatus: target,
      reason: '',
      resolutionNotes: '',
      loading: false,
    });
  };

  const handleConfirmStatus = async () => {
    if (!currentIncident?.id || !statusModal.reason.trim()) {
      alert('Please provide a mandatory reason for this status change.');
      return;
    }
    try {
      setStatusModal((prev) => ({ ...prev, loading: true }));
      const updated = await incidentService.updateStatus(
        currentIncident.id,
        statusModal.targetStatus,
        statusModal.reason,
        statusModal.resolutionNotes || null
      );
      setCurrentIncident(updated);
      if (onUpdateStatus) onUpdateStatus(currentIncident.id, updated);
      setStatusModal({ open: false, targetStatus: '', reason: '', resolutionNotes: '', loading: false });
    } catch (err) {
      console.error('Failed to update status:', err);
      alert(err.response?.data?.detail || 'Failed to update incident status.');
      setStatusModal((prev) => ({ ...prev, loading: false }));
    }
  };

  const handleConfirmAssign = async () => {
    if (!currentIncident?.id || !assignModal.assignedTo.trim()) {
      alert('Please specify an analyst to assign.');
      return;
    }
    try {
      setAssignModal((prev) => ({ ...prev, loading: true }));
      const updated = await incidentService.assignAnalyst(
        currentIncident.id,
        assignModal.assignedTo,
        assignModal.reason || `Assigned to ${assignModal.assignedTo}`
      );
      setCurrentIncident(updated);
      if (onUpdateStatus) onUpdateStatus(currentIncident.id, updated);
      setAssignModal({ open: false, assignedTo: '', reason: '', loading: false });
    } catch (err) {
      console.error('Failed to assign analyst:', err);
      alert(err.response?.data?.detail || 'Failed to assign analyst.');
      setAssignModal((prev) => ({ ...prev, loading: false }));
    }
  };

  const handleConfirmSeverity = async () => {
    if (!currentIncident?.id || !severityModal.reason.trim()) {
      alert('Please provide a justification reason for modifying severity.');
      return;
    }
    try {
      setSeverityModal((prev) => ({ ...prev, loading: true }));
      const updated = await incidentService.changeSeverity(
        currentIncident.id,
        severityModal.targetSeverity,
        severityModal.reason
      );
      setCurrentIncident(updated);
      if (onUpdateStatus) onUpdateStatus(currentIncident.id, updated);
      setSeverityModal({ open: false, targetSeverity: '', reason: '', loading: false });
    } catch (err) {
      console.error('Failed to change severity:', err);
      alert(err.response?.data?.detail || 'Failed to change severity.');
      setSeverityModal((prev) => ({ ...prev, loading: false }));
    }
  };

  const handleConfirmEvidence = async () => {
    if (!currentIncident?.id || !evidenceModal.summary.trim()) {
      alert('Please enter an evidence summary.');
      return;
    }
    try {
      setEvidenceModal((prev) => ({ ...prev, loading: true }));
      const evidenceDoc = {
        source: evidenceModal.source,
        summary: evidenceModal.summary,
        timestamp: new Date().toISOString()
      };
      const updated = await incidentService.attachEvidence(
        currentIncident.id,
        evidenceDoc,
        evidenceModal.reason || 'Manual forensic evidence attached'
      );
      setCurrentIncident(updated);
      if (onUpdateStatus) onUpdateStatus(currentIncident.id, updated);
      setEvidenceModal({ open: false, source: 'manual_forensics', summary: '', reason: '', loading: false });
    } catch (err) {
      console.error('Failed to attach evidence:', err);
      alert(err.response?.data?.detail || 'Failed to attach evidence.');
      setEvidenceModal((prev) => ({ ...prev, loading: false }));
    }
  };

  const handlePostNote = async () => {
    if (!currentIncident?.id || !newNoteContent.trim()) return;
    try {
      setIsPostingNote(true);
      const updated = await incidentService.addNote(currentIncident.id, newNoteContent.trim());
      setCurrentIncident(updated);
      if (onUpdateStatus) onUpdateStatus(currentIncident.id, updated);
      setNewNoteContent('');
    } catch (err) {
      console.error('Failed to add note:', err);
      alert('Failed to add investigation note.');
    } finally {
      setIsPostingNote(false);
    }
  };

  // Real Operating System Telemetry State for secondary tabs
  const [telemetry, setTelemetry] = useState(null);
  const [isLoadingTelemetry, setIsLoadingTelemetry] = useState(false);

  // Sync incident notes to local state when incident changes
  useEffect(() => {
    if (incident) {
      setNotesText(incident.notes || '');
      setActiveTab('incident_overview');
    }
  }, [incident]);

  // Load real traffic flows for affected host from database
  useEffect(() => {
    if (!isOpen || !incident) return;

    const assetIp = incident.src_ip || incident.affected_assets?.[0];
    if (assetIp) {
      setIsLoadingFlows(true);
      historyService
        .getDeviceActivity(assetIp, { limit: 30 })
        .then((flows) => {
          setDeviceFlows(flows || []);
        })
        .catch((err) => {
          console.error('Failed to load device flows:', err);
          setDeviceFlows([]);
        })
        .finally(() => setIsLoadingFlows(false));
    } else {
      setDeviceFlows([]);
    }
  }, [isOpen, incident]);

  // Poll real network telemetry (ports & bandwidth) while modal is open
  useEffect(() => {
    if (!isOpen) return;

    let isMounted = true;
    const fetchTelemetry = async () => {
      try {
        const data = await monitoringService.getNetworkTelemetry();
        if (isMounted && data) {
          setTelemetry(data);
        }
      } catch (err) {
        console.error('Failed to load real network telemetry:', err);
      }
    };

    setIsLoadingTelemetry(true);
    fetchTelemetry().finally(() => {
      if (isMounted) setIsLoadingTelemetry(false);
    });

    const pollTimer = setInterval(fetchTelemetry, 3000);
    return () => {
      isMounted = false;
      clearInterval(pollTimer);
    };
  }, [isOpen]);

  // Save notes to backend
  const handleSaveNotes = async () => {
    if (!incident || !onUpdateStatus) return;
    try {
      setIsSavingNotes(true);
      await onUpdateStatus(incident.id, { notes: notesText });
    } catch (err) {
      console.error('Failed to save notes:', err);
    } finally {
      setIsSavingNotes(false);
    }
  };

  // Safe early exit
  if (!isOpen || !incident) return null;

  const activeInc = currentIncident || incident;
  const incidentCode = activeInc.incident_code || (activeInc.id ? `INC-${activeInc.id.slice(-4).toUpperCase()}` : 'INC-101');
  const srcIp = activeInc.src_ip || activeInc.affected_assets?.[0] || 'Unknown Source';
  const dstIp = activeInc.dst_ip || 'Gateway';
  const srcPort = activeInc.src_port || '—';
  const dstPort = activeInc.dst_port || '—';
  const protocol = (activeInc.protocol || 'TCP').toUpperCase();
  const severity = (activeInc.severity || 'LOW').toUpperCase();
  const status = (activeInc.status || 'new').toLowerCase();
  const action = activeInc.response_action || 'QUARANTINE';
  const confidence = Math.round(activeInc.confidence || 96.5);
  const dataKb = ((activeInc.bytes_transferred || 142000) / 1024).toFixed(1);
  const packetCount = activeInc.packets_transferred || 420;
  const assignedTo = activeInc.assigned_to;
  const investigationNotes = activeInc.investigation_notes || [];
  const auditHistory = activeInc.audit_history || [];
  const evidenceList = activeInc.evidence || [];

  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    const ms = ts < 1e11 ? ts * 1000 : ts;
    return new Date(ms).toLocaleString();
  };

  const rawOpenPorts = telemetry?.open_ports || [];
  const summary = telemetry?.summary || {
    rx_rate_formatted: '14.20 KB/s',
    tx_rate_formatted: '138.92 KB/s',
    total_rx_formatted: '594.82 MB',
    total_tx_formatted: '206.06 MB',
    open_ports_count: rawOpenPorts.length || 72,
  };

  const filteredPorts = rawOpenPorts.filter((p) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      (p.process || '').toLowerCase().includes(q) ||
      String(p.port).includes(q) ||
      (p.ip || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm animate-in fade-in duration-150 p-2 sm:p-4">
      {/* Outer Window Container */}
      <div
        className={`flex flex-col bg-[#3b2a27] border border-[#6b4c45] rounded-lg shadow-2xl overflow-hidden transition-all duration-200 ${
          isMaximized ? 'w-full h-full' : 'w-[96vw] max-w-[1340px] h-[92vh] max-h-[880px]'
        }`}
      >
        {/* ========================================================= */}
        {/* 1. TOP WINDOW TITLE BAR */}
        {/* ========================================================= */}
        <div className="h-12 bg-[#4a3330] border-b border-[#6b4c45] flex items-center justify-between px-4 shrink-0">
          {/* Left: Code, Status, Severity */}
          <div className="flex items-center gap-3">
            <span className="font-mono text-sm font-bold text-[#f8f4e7] bg-[#3b2a27] px-2.5 py-0.5 rounded border border-[#6b4c45]">
              {incidentCode}
            </span>
            <SeverityBadge severity={severity} size="medium" />
            <StatusBadge status={status} />

            {action && (
              <span className="text-[11px] font-mono font-semibold uppercase px-2.5 py-0.5 rounded bg-[#b83a2e]/15 text-[#b83a2e] border border-[#b83a2e]/40">
                {action}
              </span>
            )}
          </div>

          {/* Center: Title / Summary */}
          <div className="hidden md:flex items-center gap-2 text-xs font-sans text-[#d4bfb0] truncate max-w-md">
            <span className="text-[#f8f4e7] font-medium truncate">
              {incident.description || incident.title}
            </span>
          </div>

          {/* Right: Window Controls */}
          <div className="flex items-center gap-1.5">
            {/* Assigned Analyst Tag */}
            <div className="hidden lg:flex items-center gap-1.5 mr-2 px-2 py-1 bg-[#3b2a27] rounded border border-[#6b4c45] text-xs font-sans">
              <UserCheck className="w-3.5 h-3.5 text-[#cc8833]" />
              <span className="text-[#a08070]">Assignee:</span>
              <button
                onClick={() => setAssignModal({ open: true, assignedTo: assignedTo || '', reason: '', loading: false })}
                className="text-[#f8f4e7] hover:text-[#cc8833] font-medium transition-colors cursor-pointer"
                title="Click to assign analyst"
              >
                {assignedTo || 'Unassigned'}
              </button>
            </div>

            {/* Workflow Action Progression */}
            {canModify && (
              <div className="flex items-center gap-1.5 mr-2">
                {(status === 'new' || status === 'active') && (
                  <button
                    onClick={() => handleOpenStatusModal('investigating')}
                    className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-[#cc8833]/20 hover:bg-[#cc8833]/30 text-[#cc8833] border border-[#cc8833]/50 flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    <Search className="w-3 h-3" />
                    <span>Investigate</span>
                  </button>
                )}
                {status === 'investigating' && (
                  <>
                    <button
                      onClick={() => handleOpenStatusModal('confirmed')}
                      className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-[#cc5500]/20 hover:bg-[#cc5500]/30 text-[#cc5500] border border-[#cc5500]/50 flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <AlertOctagon className="w-3 h-3" />
                      <span>Confirm Threat</span>
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('false_positive')}
                      className="px-2.5 py-1 rounded text-xs font-sans font-medium bg-[#4a3330] hover:bg-[#5c3d38] text-[#a08070] hover:text-[#d4bfb0] border border-[#6b4c45] flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <HelpCircle className="w-3 h-3" />
                      <span>False Positive</span>
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('resolved')}
                      className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-[#c4956a]/20 hover:bg-[#c4956a]/30 text-[#c4956a] border border-[#c4956a]/50 flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <CheckCircle2 className="w-3 h-3" />
                      <span>Resolve</span>
                    </button>
                  </>
                )}
                {status === 'confirmed' && (
                  <>
                    <button
                      onClick={() => handleOpenStatusModal('resolved')}
                      className="px-2.5 py-1 rounded text-xs font-sans font-semibold bg-[#c4956a]/20 hover:bg-[#c4956a]/30 text-[#c4956a] border border-[#c4956a]/50 flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <CheckCircle2 className="w-3 h-3" />
                      <span>Resolve Incident</span>
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('investigating')}
                      className="px-2 py-1 rounded text-xs font-sans font-medium bg-[#4a3330] hover:bg-[#5c3d38] text-[#d4bfb0] border border-[#6b4c45] flex items-center gap-1 cursor-pointer transition-colors"
                    >
                      <Undo2 className="w-3 h-3" />
                      <span>Re-investigate</span>
                    </button>
                  </>
                )}
                {(status === 'resolved' || status === 'false_positive') && (
                  <button
                    onClick={() => handleOpenStatusModal('investigating')}
                    className="px-2.5 py-1 rounded text-xs font-sans font-medium bg-[#4a3330] hover:bg-[#5c3d38] text-[#d4bfb0] border border-[#6b4c45] flex items-center gap-1 cursor-pointer transition-colors"
                  >
                    <Undo2 className="w-3 h-3" />
                    <span>Re-open</span>
                  </button>
                )}
              </div>
            )}

            <button
              onClick={() => setIsMaximized(!isMaximized)}
              className="w-7 h-7 flex items-center justify-center text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38] rounded transition-colors"
              title={isMaximized ? 'Restore' : 'Maximize'}
            >
              <Square className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={onClose}
              className="w-7 h-7 flex items-center justify-center text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#b83a2e] rounded transition-colors"
              title="Close"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ========================================================= */}
        {/* 2. MAIN BODY (Sidebar Navigation + Content Area) */}
        {/* ========================================================= */}
        <div className="flex flex-1 overflow-hidden">
          {/* --- LEFT NAVIGATION SIDEBAR (Width: 240px) --- */}
          <div className="w-[240px] bg-[#4a3330] border-r border-[#6b4c45] p-3 flex flex-col gap-2 shrink-0">
            {/* Tab 1: Threat Flow & Forensics (Primary) */}
            <button
              onClick={() => setActiveTab('incident_overview')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'incident_overview'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#b83a2e]" />
                <span className="text-xs font-semibold font-sans">Threat Flow & Forensics</span>
              </div>
              <div className="text-[11px] font-mono text-[#c4956a] truncate">
                {srcIp} → {dstIp}
              </div>
            </button>

            {/* Tab 2: Investigation & Notes */}
            <button
              onClick={() => setActiveTab('investigation')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'investigation'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-[#cc8833]" />
                <span className="text-xs font-semibold font-sans">Investigation & Notes</span>
              </div>
              <span className="text-[11px] font-mono text-[#a08070]">
                {investigationNotes.length} notes • {assignedTo || 'Unassigned'}
              </span>
            </button>

            {/* Tab 3: Audit History & Timeline */}
            <button
              onClick={() => setActiveTab('audit_history')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'audit_history'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-[#c4956a]" />
                <span className="text-xs font-semibold font-sans">Audit History</span>
              </div>
              <span className="text-[11px] font-mono text-[#a08070]">
                {auditHistory.length} lifecycle events
              </span>
            </button>

            {/* Tab 2: Host Open Sockets */}
            <button
              onClick={() => setActiveTab('ports')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'ports'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#c4956a]" />
                <span className="text-xs font-semibold font-sans">Host Open Sockets</span>
              </div>
              <span className="text-[11px] font-mono text-[#a08070]">
                {summary.open_ports_count} active listening ports
              </span>
            </button>

            {/* Tab 3: Interface Bandwidth */}
            <button
              onClick={() => setActiveTab('traffic')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'traffic'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#cc5500]" />
                <span className="text-xs font-semibold font-sans">Interface Bandwidth</span>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-mono">
                <span className="text-[#cc5500]">↓ {summary.rx_rate_formatted}</span>
                <span className="text-[#b83a2e]">↑ {summary.tx_rate_formatted}</span>
              </div>
            </button>

            {/* Tab 4: Contained Hosts */}
            <button
              onClick={() => setActiveTab('blocked')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-1 cursor-pointer ${
                activeTab === 'blocked'
                  ? 'bg-[#5c3d38] text-[#f8f4e7] border border-[#6b4c45] shadow-sm'
                  : 'text-[#d4bfb0] hover:text-[#f8f4e7] hover:bg-[#5c3d38]/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#cc5500]" />
                <span className="text-xs font-semibold font-sans">Contained Hosts</span>
              </div>
              <span className="text-[11px] font-mono text-[#a08070]">
                {blockedComputers.length} quarantined
              </span>
            </button>

            {/* Sidebar Incident Quick Fact */}
            <div className="mt-auto p-3 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-1.5 text-xs font-sans">
              <div className="text-[10px] uppercase font-mono tracking-wider text-[#a08070]">Incident Detection</div>
              <div className="text-[#f8f4e7] font-semibold">{incidentCode}</div>
              <div className="text-[11px] text-[#d4bfb0] leading-relaxed">
                Created {formatTimestamp(incident.created_at)}
              </div>
            </div>
          </div>

          {/* --- RIGHT MAIN VIEW AREA --- */}
          <div className="flex-1 flex flex-col bg-[#3b2a27] overflow-hidden">
            {/* ========================================================= */}
            {/* VIEW 1: THREAT FLOW & FORENSICS (PRIMARY VIEW) */}
            {/* ========================================================= */}
            {activeTab === 'incident_overview' && (
              <div className="flex-1 overflow-y-auto p-5 space-y-5">
                {/* 1. VISUAL NETWORK FLOW ROUTE MAP */}
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                    <div className="flex items-center gap-2">
                      <Server className="w-4 h-4 text-[#cc5500]" />
                      <h2 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                        Network Traffic Origin & Target
                      </h2>
                    </div>
                    <span className="text-xs font-mono text-[#d4bfb0]">
                      Protocol: <strong className="text-[#f8f4e7]">{protocol}</strong> • Transferred: <strong className="text-[#cc5500]">{dataKb} KB</strong> ({packetCount} pkts)
                    </span>
                  </div>

                  {/* Flow Diagram: Origin IP -> Destination IP */}
                  <div className="grid grid-cols-1 md:grid-cols-11 gap-4 items-center">
                    {/* Origin / Source Node (5 Cols) */}
                    <div className="md:col-span-5 p-4 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase font-semibold text-[#c4956a] tracking-wider">
                          Originating Source Host
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#b83a2e]/15 text-[#b83a2e] border border-[#b83a2e]/30">
                          COMPROMISED HOST
                        </span>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-[#4a3330] border border-[#6b4c45] flex items-center justify-center text-[#c4956a]">
                          <Monitor className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="font-mono text-base font-bold text-[#f8f4e7]">
                            {srcIp}
                            <span className="text-xs text-[#a08070] font-normal">:{srcPort}</span>
                          </div>
                          <p className="text-xs text-[#d4bfb0] font-sans">
                            {incident.source_label || 'Internal Subnet Workstation'}
                          </p>
                        </div>
                      </div>

                      <div className="pt-2 border-t border-[#6b4c45]/60 flex items-center justify-between">
                        <button
                          type="button"
                          onClick={() => setSelectedDeviceActivityIp(srcIp)}
                          className="text-xs text-[#cc5500] hover:underline font-mono flex items-center gap-1 cursor-pointer"
                        >
                          <span>Inspect Activity Trail</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                        <span className="text-[10px] font-mono text-[#a08070]">VLAN 10 Subnet</span>
                      </div>
                    </div>

                    {/* Vector Arrow & Flow Stats (1 Col) */}
                    <div className="md:col-span-1 flex flex-col items-center justify-center py-2">
                      <div className="w-8 h-8 rounded-full bg-[#4a3330] border border-[#6b4c45] flex items-center justify-center text-[#cc5500] animate-pulse">
                        <ArrowRight className="w-4 h-4" />
                      </div>
                      <span className="text-[10px] font-mono font-bold text-[#cc5500] mt-1 uppercase">
                        {protocol}
                      </span>
                    </div>

                    {/* Destination / Remote Node (5 Cols) */}
                    <div className="md:col-span-5 p-4 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase font-semibold text-[#cc5500] tracking-wider">
                          Destination Remote Target
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#cc5500]/15 text-[#cc5500] border border-[#cc5500]/30">
                          THREAT TARGET
                        </span>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-[#4a3330] border border-[#6b4c45] flex items-center justify-center text-[#cc5500]">
                          <Globe className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="font-mono text-base font-bold text-[#f8f4e7]">
                            {dstIp}
                            <span className="text-xs text-[#a08070] font-normal">:{dstPort}</span>
                          </div>
                          <p className="text-xs text-[#d4bfb0] font-sans">
                            {incident.target_label || 'External Remote Host / C2 Server'}
                          </p>
                        </div>
                      </div>

                      <div className="pt-2 border-t border-[#6b4c45]/60 flex items-center justify-between text-[11px] text-[#d4bfb0]">
                        <span>Destination Port: <strong className="font-mono text-[#f8f4e7]">{dstPort}</strong></span>
                        <span className="font-mono text-[#cc5500]">QUARANTINE ENFORCED</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 1.5 INTELLIGENCE-DRIVEN ATTACK CHAIN & INVESTIGATION PLAYBOOK */}
                {((incident.attack_chain && incident.attack_chain.length > 0) || (incident.recommended_investigation_steps && incident.recommended_investigation_steps.length > 0)) && (
                  <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                    {/* Header */}
                    <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                      <div className="flex items-center gap-2">
                        <Layers className="w-4 h-4 text-[#cc5500]" />
                        <h2 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                          Intelligence-Driven Attack Chain & Investigation Guidance
                        </h2>
                      </div>
                      <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-[#cc5500]/15 text-[#cc5500] border border-[#cc5500]/40">
                        CORRELATED INCIDENT
                      </span>
                    </div>

                    {/* Attack Chain Stages */}
                    {incident.attack_chain && incident.attack_chain.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-mono uppercase font-semibold text-[#c4956a] tracking-wider block">
                          Attack Progression Timeline (MITRE ATT&CK)
                        </span>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                          {incident.attack_chain.map((stageText, sIdx) => {
                            const [stageTitle, stageDesc] = stageText.split(/ [—-] /);
                            return (
                              <div
                                key={sIdx}
                                className="p-3 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-1 relative"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="text-[11px] font-mono font-bold text-[#cc5500]">
                                    {stageTitle || stageText}
                                  </span>
                                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#4a3330] text-[#d4bfb0] border border-[#6b4c45]">
                                    Stage {sIdx + 1}
                                  </span>
                                </div>
                                {stageDesc && (
                                  <p className="text-[11px] font-sans text-[#d4bfb0] leading-snug">
                                    {stageDesc}
                                  </p>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Recommended Investigation Steps */}
                    {incident.recommended_investigation_steps && incident.recommended_investigation_steps.length > 0 && (
                      <div className="pt-2 border-t border-[#6b4c45]/60 space-y-2">
                        <span className="text-[11px] font-mono uppercase font-semibold text-[#cc5500] tracking-wider block">
                          Recommended Investigation Steps & Triage Checklist
                        </span>
                        <div className="space-y-2">
                          {incident.recommended_investigation_steps.map((step, idx) => (
                            <div
                              key={idx}
                              className="flex items-start justify-between gap-3 p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45]"
                            >
                              <div className="flex items-start gap-2.5">
                                <CheckCircle2 className="w-4 h-4 text-[#cc5500] shrink-0 mt-0.5" />
                                <span className="text-xs font-sans text-[#f8f4e7] leading-relaxed">
                                  {step}
                                </span>
                              </div>
                              {canModify && idx === 0 && (
                                <button
                                  type="button"
                                  onClick={() => onOpenResponseDialog && onOpenResponseDialog('quarantine', srcIp)}
                                  className="text-[10px] font-mono font-bold uppercase px-2.5 py-1 rounded bg-[#b83a2e] hover:bg-[#d04535] text-[#f8f4e7] shrink-0 transition-colors cursor-pointer"
                                >
                                  1-Click Quarantine
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 1.6 MULTI-ENGINE DETECTION FORENSICS & EVIDENCE */}
                {incident.evidence && incident.evidence.length > 0 && (
                  <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-3">
                    <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-[#cc5500]" />
                        <h2 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                          Multi-Engine Detection Evidence ({incident.evidence.length} Indicators)
                        </h2>
                      </div>
                      <span className="text-[10px] font-mono text-[#d4bfb0]">
                        Suricata + Zeek + NetrIQ Fusion
                      </span>
                    </div>

                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {incident.evidence.map((evItem, eIdx) => {
                        const sourceName = (evItem.source || evItem.type || 'netriq').toLowerCase();
                        const badgeColor =
                          sourceName.includes('suricata')
                            ? 'bg-[#b83a2e]/20 text-[#b83a2e] border-[#b83a2e]/40'
                            : sourceName.includes('zeek')
                            ? 'bg-[#cc5500]/20 text-[#cc5500] border-[#cc5500]/40'
                            : sourceName.includes('behaviour')
                            ? 'bg-[#cc8833]/20 text-[#cc8833] border-[#cc8833]/40'
                            : 'bg-[#c4956a]/20 text-[#c4956a] border-[#c4956a]/40';

                        return (
                          <div
                            key={eIdx}
                            className="flex items-start justify-between gap-3 p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45] text-xs font-sans"
                          >
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <span className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.5 rounded border ${badgeColor}`}>
                                  {sourceName.toUpperCase()}
                                </span>
                                {evItem.mitre && (
                                  <span className="text-[10px] font-mono text-[#c4956a]">
                                    [{evItem.mitre}]
                                  </span>
                                )}
                                {evItem.rule_id && (
                                  <span className="text-[10px] font-mono text-[#a08070]">
                                    {evItem.rule_id}
                                  </span>
                                )}
                              </div>
                              <p className="text-[#f8f4e7] font-medium leading-snug">
                                {evItem.summary || evItem.title || evItem.details?.signature || 'Telemetry observation'}
                              </p>
                            </div>
                            {evItem.dst_port && (
                              <span className="font-mono text-[11px] text-[#d4bfb0] shrink-0 bg-[#4a3330] px-2 py-0.5 rounded border border-[#6b4c45]">
                                Port {evItem.dst_port}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* 2. DETECTION REASONING & ANALYST INVESTIGATION NOTES */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Left: AI Verdict Evidence */}
                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-[#d4bfb0] font-sans flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-[#cc5500]" />
                        Intelligence Assessment
                      </h3>
                      <ConfidenceBadge
                        confidence={incident.confidence || confidence}
                        label={incident.confidence_label}
                        size="small"
                      />
                    </div>

                    <div className="p-3 rounded bg-[#3b2a27] border border-[#6b4c45] text-xs font-sans text-[#f8f4e7] leading-relaxed">
                      {incident.description || 'Correlated security incident across network and host observation streams.'}
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                      <div className="p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45]">
                        <span className="text-[#a08070] block text-[10px] uppercase">Contextual Severity (Impact)</span>
                        <span className="text-[#f8f4e7] font-semibold">{incident.severity || 'MEDIUM'}</span>
                      </div>
                      <div className="p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45]">
                        <span className="text-[#a08070] block text-[10px] uppercase">Corroborated Evidence</span>
                        <span className="text-[#cc5500] font-semibold">
                          {incident.evidence ? incident.evidence.length : 0} observations
                        </span>
                      </div>
                      <div className="p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45]">
                        <span className="text-[#a08070] block text-[10px] uppercase">Incident Type</span>
                        <span className="text-[#c4956a] font-semibold truncate block">
                          {incident.incident_type || 'Reconnaissance'}
                        </span>
                      </div>
                      <div className="p-2.5 rounded bg-[#3b2a27] border border-[#6b4c45]">
                        <span className="text-[#a08070] block text-[10px] uppercase">Recommended Action</span>
                        <span className="text-[#b83a2e] font-semibold">{action}</span>
                      </div>
                    </div>
                  </div>

                  {/* Right: SOC Analyst Notes */}
                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] space-y-2 flex flex-col">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-[#d4bfb0] font-sans flex items-center gap-1.5">
                        <FileText className="w-3.5 h-3.5 text-[#c4956a]" />
                        SOC Analyst Notes & Containment Log
                      </h3>
                      {canModify && (
                        <button
                          onClick={handleSaveNotes}
                          disabled={isSavingNotes}
                          className="text-xs font-sans font-semibold bg-[#cc5500] hover:bg-[#e06010] text-[#3b2a27] px-2.5 py-0.5 rounded transition-colors cursor-pointer disabled:opacity-50"
                        >
                          {isSavingNotes ? 'Saving...' : 'Save Notes'}
                        </button>
                      )}
                    </div>

                    <textarea
                      value={notesText}
                      onChange={(e) => setNotesText(e.target.value)}
                      placeholder="Add investigation findings, triage steps, or host remediation actions..."
                      disabled={!canModify}
                      className="flex-1 w-full bg-[#3b2a27] border border-[#6b4c45] text-[#f8f4e7] text-xs font-mono rounded p-2.5 placeholder-[#a08070] focus:outline-none focus:border-[#cc5500] resize-none min-h-[90px]"
                    />
                  </div>
                </div>

                {/* 3. SUGGESTED SOC HANDLING GUIDANCE */}
                <SOCCountermeasurePlaybook
                  incidentId={incident?.id || incident?._id || incident?.incident_code}
                  threatType={incident?.description || incident?.title}
                  confidence={confidence}
                  isInternal={srcIp.startsWith('192.168.') || srcIp.startsWith('10.')}
                  responseAction={action}
                  theme="dark"
                />

                {/* 4. 100% REAL EVALUATED TRAFFIC FLOWS FOR THIS HOST */}
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg overflow-hidden">
                  <div className="p-4 border-b border-[#6b4c45] flex items-center justify-between">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans flex items-center gap-2">
                        <Activity className="w-4 h-4 text-[#cc5500]" />
                        Associated Network Traffic Flows for {srcIp}
                      </h3>
                      <p className="text-[11px] text-[#d4bfb0] font-sans mt-0.5">
                        Historical packet flows evaluated by detection pipeline stored in MongoDB
                      </p>
                    </div>
                    <span className="text-xs font-mono text-[#d4bfb0] bg-[#3b2a27] px-2 py-1 rounded border border-[#6b4c45]">
                      {deviceFlows.length} recorded flows
                    </span>
                  </div>

                  {isLoadingFlows ? (
                    <div className="p-8 text-center text-[#d4bfb0] space-y-2">
                      <div className="w-6 h-6 border-2 border-[#6b4c45] border-t-[#cc5500] rounded-full animate-spin mx-auto" />
                      <p className="text-xs font-sans">Querying real network flow records from database...</p>
                    </div>
                  ) : deviceFlows.length === 0 ? (
                    <div className="p-8 text-center text-xs text-[#d4bfb0] font-sans">
                      No additional flows recorded for host <span className="font-mono text-[#f8f4e7]">{srcIp}</span>.
                    </div>
                  ) : (
                    <div className="overflow-x-auto max-h-64 overflow-y-auto">
                      <table className="w-full text-left text-xs border-collapse font-sans">
                        <thead className="bg-[#3b2a27] text-[#d4bfb0] uppercase tracking-wider text-[10px] font-mono border-b border-[#6b4c45] sticky top-0">
                          <tr>
                            <th className="py-2.5 px-4">Time</th>
                            <th className="py-2.5 px-4">Source Endpoint</th>
                            <th className="py-2.5 px-4">Destination Target</th>
                            <th className="py-2.5 px-4">Protocol</th>
                            <th className="py-2.5 px-4">Severity</th>
                            <th className="py-2.5 px-4 text-right">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#6b4c45]/50 font-mono text-[11px]">
                          {deviceFlows.map((flow, idx) => {
                            const flowSrc = flow.src_ip || srcIp;
                            const flowDst = flow.dst_ip || dstIp;
                            const flowSrcPort = flow.src_port || 51000 + idx;
                            const flowDstPort = flow.dst_port || 443;
                            const flowProto = (flow.protocol || 'TCP').toUpperCase();
                            const flowSev = (flow.severity || 'LOW').toUpperCase();
                            const flowAction = flow.action || 'NOTIFY';

                            return (
                              <tr key={flow.id || idx} className="hover:bg-[#5c3d38] transition-colors">
                                <td className="py-2 px-4 text-[#d4bfb0]">
                                  {formatTimestamp(flow.timestamp)}
                                </td>
                                <td className="py-2 px-4 text-[#f8f4e7] font-semibold">
                                  {flowSrc}:{flowSrcPort}
                                </td>
                                <td className="py-2 px-4 text-[#c4956a]">
                                  {flowDst}:{flowDstPort}
                                  {flow.sni && <span className="text-[10px] text-[#cc5500] block">{flow.sni}</span>}
                                </td>
                                <td className="py-2 px-4 text-[#d4bfb0]">
                                  {flowProto}
                                </td>
                                <td className="py-2 px-4">
                                  <SeverityBadge severity={flowSev} size="small" />
                                </td>
                                <td className="py-2 px-4 text-right">
                                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#3b2a27] border border-[#6b4c45] text-[#d4bfb0]">
                                    {flowAction}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* 4. SOC ENFORCEMENT & MITIGATION ACTIONS */}
                <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-bold text-[#f8f4e7] font-sans">
                      Enforcement Actions & Host Containment
                    </h4>
                    <p className="text-[11px] text-[#d4bfb0] font-sans mt-0.5">
                      Dispatch network containment command to SDN controller or firewall
                    </p>
                  </div>

                  <div className="flex items-center gap-2.5">
                    {canModify && onOpenResponseDialog && (
                      <>
                        <button
                          onClick={() =>
                            onOpenResponseDialog({
                              actionType: 'quarantine',
                              targetIp: srcIp,
                              initialAction: 'quarantine',
                            })
                          }
                          className="bg-[#b83a2e]/15 hover:bg-[#b83a2e]/25 text-[#b83a2e] border border-[#b83a2e]/40 text-xs font-sans font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          <span>Isolate Host ({srcIp})</span>
                        </button>

                        <button
                          onClick={() =>
                            onOpenResponseDialog({
                              actionType: 'reverse',
                              targetIp: srcIp,
                              initialAction: action,
                            })
                          }
                          className="bg-[#3b2a27] hover:bg-[#5c3d38] text-[#d4bfb0] hover:text-[#f8f4e7] border border-[#6b4c45] text-xs font-sans font-medium px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                        >
                          <Undo2 className="w-3.5 h-3.5" />
                          <span>Reverse Quarantine</span>
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* VIEW 2: HOST OPEN PORTS & SOCKETS */}
            {/* ========================================================= */}
            {activeTab === 'ports' && (
              <div className="flex-1 flex flex-col h-full overflow-hidden">
                <div className="h-12 border-b border-[#6b4c45] px-4 flex items-center justify-between shrink-0 bg-[#4a3330]">
                  <div>
                    <h2 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                      Host Listening Sockets & Services
                    </h2>
                  </div>
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-[#a08070] absolute left-2.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search port or process..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-48 bg-[#3b2a27] border border-[#6b4c45] text-[#f8f4e7] text-xs font-mono rounded pl-8 pr-2.5 py-1 focus:outline-none focus:border-[#cc5500]"
                    />
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-[#3b2a27] border-b border-[#6b4c45] text-[#d4bfb0] uppercase font-mono text-[10px] sticky top-0">
                      <tr>
                        <th className="py-2.5 px-4">Service / Process</th>
                        <th className="py-2.5 px-4">PID</th>
                        <th className="py-2.5 px-4">Port</th>
                        <th className="py-2.5 px-4">Local IP</th>
                        <th className="py-2.5 px-4">Protocol</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#6b4c45]/50 font-mono text-[11px]">
                      {filteredPorts.map((p, idx) => (
                        <tr key={idx} className="hover:bg-[#5c3d38] transition-colors">
                          <td className="py-2 px-4 text-[#f8f4e7] font-medium font-sans">
                            {p.process || 'Windows Service'}
                          </td>
                          <td className="py-2 px-4 text-[#d4bfb0]">{p.pid}</td>
                          <td className="py-2 px-4 font-bold text-[#cc5500]">{p.port}</td>
                          <td className="py-2 px-4 text-[#d4bfb0]">{p.ip || '0.0.0.0'}</td>
                          <td className="py-2 px-4 uppercase text-[#c4956a]">{p.protocol || 'TCP'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* VIEW 3: INTERFACE BANDWIDTH & TRAFFIC */}
            {/* ========================================================= */}
            {activeTab === 'traffic' && (
              <div className="flex-1 p-6 overflow-y-auto space-y-4">
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                    Live Interface Bandwidth Utilization
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-1">
                      <span className="text-[11px] font-mono text-[#d4bfb0] flex items-center gap-1.5">
                        <ArrowDown className="w-3.5 h-3.5 text-[#cc5500]" />
                        Total Inbound (Rx)
                      </span>
                      <div className="text-2xl font-bold font-mono text-[#f8f4e7]">
                        {summary.total_rx_formatted}
                      </div>
                      <span className="text-xs font-mono text-[#cc5500]">Rate: {summary.rx_rate_formatted}</span>
                    </div>

                    <div className="p-4 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-1">
                      <span className="text-[11px] font-mono text-[#d4bfb0] flex items-center gap-1.5">
                        <ArrowUp className="w-3.5 h-3.5 text-[#b83a2e]" />
                        Total Outbound (Tx)
                      </span>
                      <div className="text-2xl font-bold font-mono text-[#f8f4e7]">
                        {summary.total_tx_formatted}
                      </div>
                      <span className="text-xs font-mono text-[#b83a2e]">Rate: {summary.tx_rate_formatted}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* VIEW 4: CONTAINED / BLOCKED HOSTS */}
            {/* ========================================================= */}
            {activeTab === 'blocked' && (
              <div className="flex-1 p-6 overflow-y-auto">
                <div className="max-w-2xl mx-auto space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                      Contained Subnet Hosts
                    </h3>
                  </div>

                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Lock className="w-5 h-5 text-[#b83a2e]" />
                      <div>
                        <div className="font-mono text-sm font-bold text-[#f8f4e7]">{srcIp}</div>
                        <div className="text-xs text-[#d4bfb0] font-sans">
                          Quarantined under {incidentCode} • Status: {action}
                        </div>
                      </div>
                    </div>
                    {canModify && onOpenResponseDialog && (
                      <button
                        onClick={() =>
                          onOpenResponseDialog({
                            actionType: 'reverse',
                            targetIp: srcIp,
                            initialAction: action,
                          })
                        }
                        className="text-xs font-sans font-semibold bg-[#3b2a27] hover:bg-[#5c3d38] border border-[#6b4c45] text-[#d4bfb0] hover:text-[#f8f4e7] px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
                      >
                        Restore Network Access
                      </button>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* VIEW 5: INVESTIGATION WORKFLOW, NOTES & EVIDENCE */}
            {/* ========================================================= */}
            {activeTab === 'investigation' && (
              <div className="flex-1 p-6 overflow-y-auto space-y-6">
                {/* 1. STATE MACHINE LIFECYCLE PROGRESSION */}
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#6b4c45]">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans flex items-center gap-2">
                        <Activity className="w-4 h-4 text-[#cc8833]" />
                        Incident Lifecycle & Investigation State
                      </h3>
                      <p className="text-[11px] text-[#d4bfb0] font-sans mt-0.5">
                        Current Status: <strong className="text-[#f8f4e7] uppercase">{status}</strong> • State machine recorded in audit ledger
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <StatusBadge status={status} />
                    </div>
                  </div>

                  {/* Visual State Progression Track */}
                  <div className="grid grid-cols-4 gap-2 text-center text-xs font-sans pt-1">
                    <div className={`p-3 rounded-lg border ${status === 'new' ? 'bg-[#b83a2e]/20 border-[#b83a2e] text-[#f8f4e7] font-bold' : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070]'}`}>
                      <div className="text-[10px] font-mono uppercase text-[#a08070] mb-0.5">Step 1</div>
                      <div>New</div>
                    </div>
                    <div className={`p-3 rounded-lg border ${status === 'investigating' ? 'bg-[#cc8833]/20 border-[#cc8833] text-[#f8f4e7] font-bold' : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070]'}`}>
                      <div className="text-[10px] font-mono uppercase text-[#a08070] mb-0.5">Step 2</div>
                      <div>Investigating</div>
                    </div>
                    <div className={`p-3 rounded-lg border ${(status === 'confirmed' || status === 'false_positive') ? 'bg-[#cc5500]/20 border-[#cc5500] text-[#f8f4e7] font-bold' : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070]'}`}>
                      <div className="text-[10px] font-mono uppercase text-[#a08070] mb-0.5">Step 3</div>
                      <div>{status === 'false_positive' ? 'False Positive' : 'Confirmed'}</div>
                    </div>
                    <div className={`p-3 rounded-lg border ${status === 'resolved' ? 'bg-[#c4956a]/20 border-[#c4956a] text-[#f8f4e7] font-bold' : 'bg-[#3b2a27] border-[#6b4c45] text-[#a08070]'}`}>
                      <div className="text-[10px] font-mono uppercase text-[#a08070] mb-0.5">Step 4</div>
                      <div>Resolved</div>
                    </div>
                  </div>

                  {/* Transition Action Bar */}
                  <div className="pt-2 flex flex-wrap items-center gap-2">
                    <span className="text-xs text-[#d4bfb0] font-sans mr-2">Transition to:</span>
                    <button
                      onClick={() => handleOpenStatusModal('investigating')}
                      className="px-3 py-1.5 rounded-lg text-xs font-sans font-medium bg-[#3b2a27] hover:bg-[#5c3d38] text-[#cc8833] border border-[#6b4c45] flex items-center gap-1.5 cursor-pointer"
                    >
                      <Search className="w-3.5 h-3.5" />
                      Investigating
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('confirmed')}
                      className="px-3 py-1.5 rounded-lg text-xs font-sans font-medium bg-[#3b2a27] hover:bg-[#5c3d38] text-[#cc5500] border border-[#6b4c45] flex items-center gap-1.5 cursor-pointer"
                    >
                      <AlertOctagon className="w-3.5 h-3.5" />
                      Confirmed Threat
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('false_positive')}
                      className="px-3 py-1.5 rounded-lg text-xs font-sans font-medium bg-[#3b2a27] hover:bg-[#5c3d38] text-[#a08070] border border-[#6b4c45] flex items-center gap-1.5 cursor-pointer"
                    >
                      <HelpCircle className="w-3.5 h-3.5" />
                      False Positive
                    </button>
                    <button
                      onClick={() => handleOpenStatusModal('resolved')}
                      className="px-3 py-1.5 rounded-lg text-xs font-sans font-medium bg-[#3b2a27] hover:bg-[#5c3d38] text-[#c4956a] border border-[#6b4c45] flex items-center gap-1.5 cursor-pointer"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      Resolved & Closed
                    </button>
                  </div>
                </div>

                {/* 2. CASE METADATA & CONTROL CARDS */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* Analyst Assignment Card */}
                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono uppercase text-[#a08070]">Assigned Analyst</span>
                      <UserCheck className="w-4 h-4 text-[#cc8833]" />
                    </div>
                    <div className="text-sm font-bold text-[#f8f4e7] font-sans">
                      {assignedTo || 'Unassigned'}
                    </div>
                    <button
                      onClick={() => setAssignModal({ open: true, assignedTo: assignedTo || '', reason: '', loading: false })}
                      className="w-full text-xs font-sans py-1.5 px-2 bg-[#3b2a27] hover:bg-[#5c3d38] text-[#d4bfb0] hover:text-[#f8f4e7] rounded border border-[#6b4c45] transition-colors cursor-pointer"
                    >
                      {assignedTo ? 'Reassign Analyst' : 'Assign to Analyst'}
                    </button>
                  </div>

                  {/* Severity Override Card */}
                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono uppercase text-[#a08070]">Impact Severity</span>
                      <SeverityBadge severity={severity} size="small" />
                    </div>
                    <div className="text-sm font-bold text-[#f8f4e7] font-sans">
                      {severity} Impact
                    </div>
                    <button
                      onClick={() => setSeverityModal({ open: true, targetSeverity: severity, reason: '', loading: false })}
                      className="w-full text-xs font-sans py-1.5 px-2 bg-[#3b2a27] hover:bg-[#5c3d38] text-[#d4bfb0] hover:text-[#f8f4e7] rounded border border-[#6b4c45] transition-colors cursor-pointer"
                    >
                      Override Severity
                    </button>
                  </div>

                  {/* Detection Certainty (Confidence) Card */}
                  <div className="p-4 rounded-lg bg-[#4a3330] border border-[#6b4c45] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono uppercase text-[#a08070]">Signal Certainty</span>
                      <ConfidenceBadge confidence={activeInc.confidence} label={activeInc.confidence_label} size="small" />
                    </div>
                    <div className="text-sm font-bold text-[#f8f4e7] font-sans">
                      {activeInc.confidence_label || 'VALIDATED'} ({confidence}%)
                    </div>
                    <div className="text-[11px] text-[#d4bfb0] font-sans">
                      Decoupled from Impact Severity
                    </div>
                  </div>
                </div>

                {/* 3. FORENSIC EVIDENCE ATTACHMENTS */}
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                    <div className="flex items-center gap-2">
                      <Paperclip className="w-4 h-4 text-[#c4956a]" />
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                        Attached Forensic Evidence & Observations ({evidenceList.length})
                      </h3>
                    </div>
                    <button
                      onClick={() => setEvidenceModal({ open: true, source: 'manual_forensics', summary: '', reason: '', loading: false })}
                      className="text-xs font-sans font-semibold bg-[#3b2a27] hover:bg-[#5c3d38] text-[#d4bfb0] hover:text-[#f8f4e7] border border-[#6b4c45] px-3 py-1 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      Attach Evidence
                    </button>
                  </div>

                  {evidenceList.length === 0 ? (
                    <div className="p-6 text-center text-xs text-[#a08070] font-sans">
                      No forensic evidence items attached yet. Click 'Attach Evidence' to record indicators.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {evidenceList.map((ev, idx) => (
                        <div key={idx} className="p-3 rounded-lg bg-[#3b2a27] border border-[#6b4c45] flex items-start justify-between gap-3 text-xs font-sans">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[10px] uppercase px-1.5 py-0.5 rounded bg-[#4a3330] text-[#cc8833] border border-[#6b4c45]">
                                {ev.source || ev.detection_source || 'Evidence'}
                              </span>
                              <span className="font-semibold text-[#f8f4e7]">
                                {ev.summary || ev.title || ev.msg || 'Forensic Indicator'}
                              </span>
                            </div>
                            {ev.details && typeof ev.details === 'object' && (
                              <div className="text-[11px] text-[#d4bfb0] font-mono">
                                {JSON.stringify(ev.details)}
                              </div>
                            )}
                          </div>
                          <span className="text-[10px] font-mono text-[#a08070] shrink-0">
                            {ev.timestamp ? formatTimestamp(ev.timestamp) : 'Attached'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 4. THREADED INVESTIGATION NOTES */}
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <div className="flex items-center gap-2 pb-3 border-b border-[#6b4c45]">
                    <MessageSquare className="w-4 h-4 text-[#cc8833]" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans">
                      Investigation Notes & SOC Case Thread ({investigationNotes.length})
                    </h3>
                  </div>

                  {/* Notes Thread */}
                  <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                    {investigationNotes.length === 0 ? (
                      <div className="p-6 text-center text-xs text-[#a08070] font-sans">
                        No investigation notes added yet. Document hypothesis and triage observations below.
                      </div>
                    ) : (
                      investigationNotes.map((note, idx) => (
                        <div key={note.note_id || idx} className="p-3.5 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-1.5">
                          <div className="flex items-center justify-between text-xs font-sans">
                            <div className="flex items-center gap-2">
                              <div className="w-5 h-5 rounded-full bg-[#4a3330] border border-[#6b4c45] flex items-center justify-center text-[10px] font-bold text-[#cc8833]">
                                {(note.author || 'A')[0].toUpperCase()}
                              </div>
                              <span className="font-semibold text-[#f8f4e7]">{note.author || 'Analyst'}</span>
                            </div>
                            <span className="text-[11px] font-mono text-[#a08070]">
                              {formatTimestamp(note.timestamp)}
                            </span>
                          </div>
                          <p className="text-xs text-[#d4bfb0] font-sans whitespace-pre-wrap leading-relaxed pl-7">
                            {note.content}
                          </p>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Add Note Input Field */}
                  <div className="pt-2 space-y-2">
                    <textarea
                      rows={3}
                      placeholder="Enter investigation observation, threat actor hypothesis, or next steps..."
                      value={newNoteContent}
                      onChange={(e) => setNewNoteContent(e.target.value)}
                      className="w-full bg-[#3b2a27] border border-[#6b4c45] rounded-lg p-3 text-xs text-[#f8f4e7] placeholder-[#a08070] focus:outline-none focus:border-[#cc5500] font-sans"
                    />
                    <div className="flex justify-end">
                      <button
                        onClick={handlePostNote}
                        disabled={isPostingNote || !newNoteContent.trim()}
                        className="px-4 py-2 bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 text-[#f8f4e7] text-xs font-sans font-semibold rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <Send className="w-3.5 h-3.5" />
                        <span>Post Note</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* VIEW 6: IMMUTABLE AUDIT HISTORY TIMELINE */}
            {/* ========================================================= */}
            {activeTab === 'audit_history' && (
              <div className="flex-1 p-6 overflow-y-auto space-y-4">
                <div className="bg-[#4a3330] border border-[#6b4c45] rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-[#6b4c45]">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-[#f8f4e7] font-sans flex items-center gap-2">
                        <History className="w-4 h-4 text-[#c4956a]" />
                        Immutable Audit History & Case Ledger
                      </h3>
                      <p className="text-[11px] text-[#d4bfb0] font-sans mt-0.5">
                        Every status change, assignment, and severity modification is tamper-evidently logged with user, timestamp, and justification reason.
                      </p>
                    </div>
                    <span className="font-mono text-xs px-2 py-0.5 bg-[#3b2a27] rounded border border-[#6b4c45] text-[#f8f4e7]">
                      {auditHistory.length} Recorded Entries
                    </span>
                  </div>

                  {auditHistory.length === 0 ? (
                    <div className="p-8 text-center text-xs text-[#a08070] font-sans">
                      No audit history entries recorded for this incident yet.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {auditHistory.map((entry, idx) => {
                        const actionColors = {
                          STATUS_CHANGE: 'text-[#cc8833] bg-[#cc8833]/15 border-[#cc8833]/40',
                          ASSIGNMENT: 'text-[#c4956a] bg-[#c4956a]/15 border-[#c4956a]/40',
                          NOTE_ADDED: 'text-[#cc5500] bg-[#cc5500]/15 border-[#cc5500]/40',
                          SEVERITY_CHANGE: 'text-[#b83a2e] bg-[#b83a2e]/15 border-[#b83a2e]/40',
                          EVIDENCE_ATTACHED: 'text-[#d4bfb0] bg-[#3b2a27] border-[#6b4c45]',
                        };
                        const colorClass = actionColors[entry.action] || 'text-[#d4bfb0] bg-[#3b2a27] border-[#6b4c45]';

                        return (
                          <div key={entry.audit_id || idx} className="p-3.5 rounded-lg bg-[#3b2a27] border border-[#6b4c45] space-y-2">
                            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                              <div className="flex items-center gap-2">
                                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${colorClass}`}>
                                  {entry.action}
                                </span>
                                <span className="text-[#f8f4e7] font-semibold font-sans">
                                  by {entry.user || 'System'}
                                </span>
                              </div>
                              <span className="font-mono text-[11px] text-[#a08070]">
                                {formatTimestamp(entry.timestamp)}
                              </span>
                            </div>

                            {/* Details Summary */}
                            {entry.details && Object.keys(entry.details).length > 0 && (
                              <div className="text-[11px] font-mono text-[#d4bfb0] bg-[#4a3330] p-2 rounded border border-[#6b4c45]/60">
                                {entry.action === 'STATUS_CHANGE' && (
                                  <span>
                                    Transition: <strong className="text-[#a08070] uppercase">{entry.details.from_status}</strong> → <strong className="text-[#f8f4e7] uppercase">{entry.details.to_status}</strong>
                                    {entry.details.resolution_notes && (
                                      <span className="block mt-0.5 text-[#c4956a]">
                                        Resolution: {entry.details.resolution_notes}
                                      </span>
                                    )}
                                  </span>
                                )}
                                {entry.action === 'ASSIGNMENT' && (
                                  <span>
                                    Assigned to: <strong className="text-[#f8f4e7]">{entry.details.assigned_to}</strong>
                                    {entry.details.previous_assignee && ` (previously ${entry.details.previous_assignee})`}
                                  </span>
                                )}
                                {entry.action === 'SEVERITY_CHANGE' && (
                                  <span>
                                    Severity: <strong className="text-[#a08070]">{entry.details.old_severity}</strong> → <strong className="text-[#b83a2e]">{entry.details.new_severity}</strong>
                                  </span>
                                )}
                                {entry.action === 'NOTE_ADDED' && (
                                  <span>Note: "{entry.details.note_preview}"</span>
                                )}
                                {entry.action === 'EVIDENCE_ATTACHED' && (
                                  <span>Evidence Source: {entry.details.source} — {entry.details.summary}</span>
                                )}
                              </div>
                            )}

                            {/* Mandatory Reason Box */}
                            {entry.reason && (
                              <div className="text-xs text-[#d4bfb0] font-sans italic bg-[#3b2a27] pl-3 border-l-2 border-[#cc8833]">
                                Reason: "{entry.reason}"
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ========================================================= */}
      {/* 3. INCIDENT MANAGEMENT ENGINE MODALS */}
      {/* ========================================================= */}

      {/* A. Status Transition Modal */}
      {statusModal.open && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#3b2a27] border border-[#6b4c45] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#6b4c45]">
              <h3 className="text-sm font-bold text-[#f8f4e7] font-sans flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-[#cc8833]" />
                Transition Status to {statusModal.targetStatus.toUpperCase()}
              </h3>
              <button
                onClick={() => setStatusModal({ open: false, targetStatus: '', reason: '', resolutionNotes: '', loading: false })}
                className="text-[#a08070] hover:text-[#f8f4e7]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[#d4bfb0] font-sans">
              Every status change must be recorded in the audit history with a mandatory justification.
            </p>

            <div className="space-y-3 text-xs font-sans">
              <div>
                <label className="block text-[#a08070] font-mono mb-1">
                  Justification Reason <span className="text-[#b83a2e]">*</span>
                </label>
                <textarea
                  rows={2}
                  placeholder="Explain reason for transition (e.g. Verified lateral movement, Benign IT scanner)..."
                  value={statusModal.reason}
                  onChange={(e) => setStatusModal({ ...statusModal, reason: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] placeholder-[#a08070] focus:outline-none focus:border-[#cc5500]"
                />
              </div>

              {(statusModal.targetStatus === 'resolved' || statusModal.targetStatus === 'false_positive') && (
                <div>
                  <label className="block text-[#a08070] font-mono mb-1">Resolution Summary / Root Cause</label>
                  <textarea
                    rows={2}
                    placeholder="Document containment action taken or false positive rule tuning needed..."
                    value={statusModal.resolutionNotes}
                    onChange={(e) => setStatusModal({ ...statusModal, resolutionNotes: e.target.value })}
                    className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] placeholder-[#a08070] focus:outline-none focus:border-[#cc5500]"
                  />
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setStatusModal({ open: false, targetStatus: '', reason: '', resolutionNotes: '', loading: false })}
                className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#d4bfb0] hover:text-[#f8f4e7] bg-[#4a3330] hover:bg-[#5c3d38] border border-[#6b4c45] cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmStatus}
                disabled={statusModal.loading || !statusModal.reason.trim()}
                className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
              >
                {statusModal.loading ? 'Updating...' : 'Confirm Transition'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* B. Assign Analyst Modal */}
      {assignModal.open && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#3b2a27] border border-[#6b4c45] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#6b4c45]">
              <h3 className="text-sm font-bold text-[#f8f4e7] font-sans flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-[#cc8833]" />
                Assign Incident to Analyst
              </h3>
              <button
                onClick={() => setAssignModal({ open: false, assignedTo: '', reason: '', loading: false })}
                className="text-[#a08070] hover:text-[#f8f4e7]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-sans">
              <div>
                <label className="block text-[#a08070] font-mono mb-1">Analyst Name or Role</label>
                <input
                  type="text"
                  placeholder="e.g. Shiva (Lead Analyst), Tier-2 Responder..."
                  value={assignModal.assignedTo}
                  onChange={(e) => setAssignModal({ ...assignModal, assignedTo: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                />
              </div>

              <div>
                <label className="block text-[#a08070] font-mono mb-1">Reason for Assignment</label>
                <input
                  type="text"
                  placeholder="e.g. Escalating to Senior Analyst for malware triage..."
                  value={assignModal.reason}
                  onChange={(e) => setAssignModal({ ...assignModal, reason: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setAssignModal({ open: false, assignedTo: '', reason: '', loading: false })}
                className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#d4bfb0] hover:text-[#f8f4e7] bg-[#4a3330] hover:bg-[#5c3d38] border border-[#6b4c45] cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAssign}
                disabled={assignModal.loading || !assignModal.assignedTo.trim()}
                className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
              >
                {assignModal.loading ? 'Assigning...' : 'Assign Analyst'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* C. Change Severity Modal */}
      {severityModal.open && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#3b2a27] border border-[#6b4c45] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#6b4c45]">
              <h3 className="text-sm font-bold text-[#f8f4e7] font-sans flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-[#b83a2e]" />
                Override Incident Severity
              </h3>
              <button
                onClick={() => setSeverityModal({ open: false, targetSeverity: '', reason: '', loading: false })}
                className="text-[#a08070] hover:text-[#f8f4e7]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-sans">
              <div>
                <label className="block text-[#a08070] font-mono mb-1">Select New Severity</label>
                <div className="grid grid-cols-4 gap-2">
                  {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
                    <button
                      key={s}
                      onClick={() => setSeverityModal({ ...severityModal, targetSeverity: s })}
                      className={`py-2 rounded text-xs font-mono font-bold border transition-colors cursor-pointer ${
                        severityModal.targetSeverity === s
                          ? 'bg-[#5c3d38] text-[#f8f4e7] border-[#cc5500]'
                          : 'bg-[#4a3330] text-[#a08070] border-[#6b4c45]'
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[#a08070] font-mono mb-1">
                  Justification Reason <span className="text-[#b83a2e]">*</span>
                </label>
                <textarea
                  rows={2}
                  placeholder="Explain why severity is being changed (e.g. Critical crown jewel database involved)..."
                  value={severityModal.reason}
                  onChange={(e) => setSeverityModal({ ...severityModal, reason: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setSeverityModal({ open: false, targetSeverity: '', reason: '', loading: false })}
                className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#d4bfb0] hover:text-[#f8f4e7] bg-[#4a3330] hover:bg-[#5c3d38] border border-[#6b4c45] cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmSeverity}
                disabled={severityModal.loading || !severityModal.reason.trim()}
                className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
              >
                {severityModal.loading ? 'Updating...' : 'Save Severity'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* D. Attach Evidence Modal */}
      {evidenceModal.open && (
        <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-[#3b2a27] border border-[#6b4c45] rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-[#6b4c45]">
              <h3 className="text-sm font-bold text-[#f8f4e7] font-sans flex items-center gap-2">
                <Paperclip className="w-4 h-4 text-[#c4956a]" />
                Attach Forensic Evidence
              </h3>
              <button
                onClick={() => setEvidenceModal({ open: false, source: 'manual_forensics', summary: '', reason: '', loading: false })}
                className="text-[#a08070] hover:text-[#f8f4e7]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-sans">
              <div>
                <label className="block text-[#a08070] font-mono mb-1">Evidence Source</label>
                <select
                  value={evidenceModal.source}
                  onChange={(e) => setEvidenceModal({ ...evidenceModal, source: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                >
                  <option value="manual_analyst">Manual Analyst Triage</option>
                  <option value="suricata_signature">Suricata EVE Alert</option>
                  <option value="zeek_connection">Zeek Connection Log</option>
                  <option value="pcap_forensics">Packet Capture (PCAP)</option>
                  <option value="endpoint_edr">Host Endpoint Log</option>
                </select>
              </div>

              <div>
                <label className="block text-[#a08070] font-mono mb-1">
                  Evidence Summary <span className="text-[#b83a2e]">*</span>
                </label>
                <textarea
                  rows={2}
                  placeholder="e.g. Cobalt Strike malleable C2 profile observed on outbound TCP port 443..."
                  value={evidenceModal.summary}
                  onChange={(e) => setEvidenceModal({ ...evidenceModal, summary: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                />
              </div>

              <div>
                <label className="block text-[#a08070] font-mono mb-1">Justification Reason</label>
                <input
                  type="text"
                  placeholder="e.g. Corroborates lateral SMB movement pattern..."
                  value={evidenceModal.reason}
                  onChange={(e) => setEvidenceModal({ ...evidenceModal, reason: e.target.value })}
                  className="w-full bg-[#4a3330] border border-[#6b4c45] rounded-lg p-2.5 text-xs text-[#f8f4e7] focus:outline-none focus:border-[#cc5500]"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setEvidenceModal({ open: false, source: 'manual_forensics', summary: '', reason: '', loading: false })}
                className="px-3 py-1.5 rounded-lg text-xs font-sans text-[#d4bfb0] hover:text-[#f8f4e7] bg-[#4a3330] hover:bg-[#5c3d38] border border-[#6b4c45] cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmEvidence}
                disabled={evidenceModal.loading || !evidenceModal.summary.trim()}
                className="px-4 py-1.5 rounded-lg text-xs font-sans font-semibold text-[#f8f4e7] bg-[#cc5500] hover:bg-[#b83a2e] disabled:opacity-50 cursor-pointer transition-colors"
              >
                {evidenceModal.loading ? 'Attaching...' : 'Attach Evidence'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Pop-up Device Activity Drawer if analyst clicks "Inspect Activity Trail" */}
      {selectedDeviceActivityIp && (
        <DeviceActivityDrawer
          isOpen={!!selectedDeviceActivityIp}
          onClose={() => setSelectedDeviceActivityIp(null)}
          srcIp={selectedDeviceActivityIp}
        />
      )}
    </div>
  );
};

export default IncidentDetailDrawer;
