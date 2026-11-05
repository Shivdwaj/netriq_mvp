import api from './api';

export const managementService = {
  /**
   * Registers a new software sensor daemon (Suricata, Zeek, NetrIQ Collector).
   * Returns API key for daemon authentication.
   */
  async registerSensor(payload) {
    const response = await api.post('/management/sensors/register', payload);
    return response.data;
  },

  /**
   * Lists software sensors belonging to the authenticated tenant organisation.
   */
  async getSensors() {
    const response = await api.get('/management/sensors');
    return response.data;
  },

  /**
   * Retrieves active detection rule manifest distributed to sensors.
   */
  async getSensorRules(sensorId) {
    const response = await api.get(`/management/sensors/${sensorId}/rules`);
    return response.data;
  },

  /**
   * Remotely updates software sensor daemon configuration.
   */
  async updateSensorConfig(sensorId, config) {
    const response = await api.patch(`/management/sensors/${sensorId}/config`, config);
    return response.data;
  },

  /**
   * Retrieves fleet audit matrix of daemon software versions vs current benchmark releases.
   */
  async getFleetVersionMatrix() {
    const response = await api.get('/management/fleet/versions');
    return response.data;
  },

  /**
   * Retrieves customer organisation profile with tenant isolation.
   */
  async getOrganisation(tenantId) {
    const response = await api.get(`/management/organisations/${tenantId}`);
    return response.data;
  },

  /**
   * Provisions a new customer organisation.
   */
  async registerOrganisation(payload) {
    const response = await api.post('/management/organisations', payload);
    return response.data;
  },

  /**
   * Simulates a daemon heartbeat for testing/demo.
   */
  async sendHeartbeat(sensorId, heartbeatData, apiKey = null) {
    const headers = apiKey ? { 'X-Sensor-Key': apiKey } : {};
    const response = await api.post('/management/sensors/heartbeat', {
      sensor_id: sensorId,
      ...heartbeatData
    }, { headers });
    return response.data;
  }
};

