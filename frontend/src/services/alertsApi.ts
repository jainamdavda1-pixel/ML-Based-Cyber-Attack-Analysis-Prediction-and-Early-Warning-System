import { fetchApi } from './api';
import { DashboardSummary, AlertItem } from '../types/alert';

export const alertsApi = {
  getDashboardSummary: (): Promise<DashboardSummary> => {
    return fetchApi<DashboardSummary>('/dashboard/summary');
  },

  getHistory: (limit: number = 100, dataset?: string, riskLevel?: string): Promise<AlertItem[]> => {
    const params = new URLSearchParams();
    params.append('limit', limit.toString());
    if (dataset) params.append('dataset', dataset);
    if (riskLevel) params.append('risk_level', riskLevel);
    return fetchApi<AlertItem[]>(`/history?${params.toString()}`);
  }
};
