import api from './api';

export const incidentService = {
  /**
   * Retrieves incidents from the backend.
   * Scoped to the authenticated user's organisation.
   */
  async getIncidents(limit = 100) {
    const response = await api.get('/incidents', { params: { limit } });
    return response.data;
  },

  async getIncident(incidentId) {
    const response = await api.get(`/incidents/${incidentId}`);
    return response.data;
  },

  /**
   * Transitions status along state machine (New -> Investigating -> Confirmed/False Positive -> Resolved)
   * with mandatory reason recorded in immutable audit log.
   */
  async updateStatus(incidentId, status, reason, resolutionNotes = null) {
    const response = await api.patch(`/incidents/${incidentId}/status`, {
      status,
      reason,
      resolution_notes: resolutionNotes
    });
    return response.data;
  },

  /**
   * Assigns incident to an analyst.
   */
  async assignAnalyst(incidentId, assignedTo, reason = null) {
    const response = await api.post(`/incidents/${incidentId}/assign`, {
      assigned_to: assignedTo,
      reason
    });
    return response.data;
  },

  /**
   * Appends a threaded investigation note.
   */
  async addNote(incidentId, content) {
    const response = await api.post(`/incidents/${incidentId}/notes`, { content });
    return response.data;
  },

  /**
   * Overrides incident severity with reason logged in audit trail.
   */
  async changeSeverity(incidentId, severity, reason) {
    const response = await api.patch(`/incidents/${incidentId}/severity`, {
      severity,
      reason
    });
    return response.data;
  },

  /**
   * Attaches new forensic indicator or event.
   */
  async attachEvidence(incidentId, evidence, reason = null) {
    const response = await api.post(`/incidents/${incidentId}/evidence`, {
      evidence,
      reason
    });
    return response.data;
  },

  /**
   * Retrieves chronological audit history timeline.
   */
  async getAuditHistory(incidentId) {
    const response = await api.get(`/incidents/${incidentId}/audit-history`);
    return response.data;
  },

  /**
   * Legacy update method.
   */
  async updateIncident(incidentId, { status, notes }) {
    const payload = {};
    if (status) payload.status = status;
    if (notes !== undefined) payload.notes = notes;

    const response = await api.patch(`/incidents/${incidentId}`, payload);
    return response.data;
  },

  /**
   * Retrieves tailored NIST SP 800-61 countermeasures & SOC runbook for an incident.
   */
  async getCountermeasures(incidentId) {
    const response = await api.get(`/incidents/${incidentId}/countermeasures`);
    return response.data;
  },
};
