import api from './api';

export const rulesService = {
  async getRules() {
    const response = await api.get('/rules');
    return response.data;
  },

  async updateRule(ruleId, updates) {
    const response = await api.put(`/rules/${ruleId}`, updates);
    return response.data;
  },

  async distributeRules() {
    const response = await api.post('/rules/distribute');
    return response.data;
  },
};

export default rulesService;
