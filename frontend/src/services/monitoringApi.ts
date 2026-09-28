import { fetchApi } from './api';
import { MonitoringStatus, MonitoringSession } from '../types/monitoring';
import { NetworkFlow } from '../types/traffic';

export const monitoringApi = {
  getInterfaces: () =>
    fetchApi<{ permitted_interfaces: string[] }>('/monitoring/interfaces'),

  getStatus: () =>
    fetchApi<MonitoringStatus>('/monitoring/status'),

  startMonitoring: (iface: string, dataset = 'cicids2017') =>
    fetchApi<any>('/monitoring/start', {
      method: 'POST',
      body: JSON.stringify({ interface: iface, dataset }),
    }),

  stopMonitoring: () =>
    fetchApi<any>('/monitoring/stop', {
      method: 'POST',
    }),

  getStatistics: () =>
    fetchApi<{ current_session: MonitoringStatus; past_sessions: MonitoringSession[] }>('/monitoring/statistics'),

  getLiveFlows: (limit = 50) =>
    fetchApi<NetworkFlow[]>(`/monitoring/flows?limit=${limit}`),
};
