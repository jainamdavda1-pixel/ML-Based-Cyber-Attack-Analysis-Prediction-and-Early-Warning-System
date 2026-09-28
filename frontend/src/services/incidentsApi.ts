import { fetchApi } from './api';
import { Incident } from '../types/incident';

export const incidentsApi = {
  listIncidents: (status?: string, severity?: string, limit = 50) => {
    let url = `/incidents?limit=${limit}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    return fetchApi<Incident[]>(url);
  },

  getIncident: (incidentId: string) =>
    fetchApi<Incident>(`/incidents/${incidentId}`),

  updateIncident: (incidentId: string, data: { status?: string; notes?: string; analyst?: string }) =>
    fetchApi<Incident>(`/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  getExplanations: (incidentId: string) =>
    fetchApi<any>(`/incidents/${incidentId}/explanations`),
};
