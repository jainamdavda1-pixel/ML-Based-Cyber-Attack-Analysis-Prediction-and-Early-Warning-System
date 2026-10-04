import { fetchApi } from './api';
import { MonitoringStatus, MonitoringSession, InterfaceInfo, LiveNetworkFlow } from '../types/monitoring';

export const monitoringApi = {
  getInterfaces: () =>
    fetchApi<{ permitted_interfaces: (string | InterfaceInfo)[] }>('/monitoring/interfaces'),

  getStatus: () =>
    fetchApi<MonitoringStatus>('/monitoring/status'),

  startMonitoring: (iface: string, dataset = 'generalized') =>
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
    fetchApi<LiveNetworkFlow[]>(`/monitoring/flows?limit=${limit}`),
};
