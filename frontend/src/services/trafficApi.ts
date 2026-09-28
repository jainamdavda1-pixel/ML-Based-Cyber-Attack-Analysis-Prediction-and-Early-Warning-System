import { fetchApi, uploadFileApi } from './api';
import { AnalysisJob, NetworkFlow } from '../types/traffic';

export const trafficApi = {
  uploadTrafficFile: (formData: FormData) =>
    uploadFileApi<any>('/traffic/upload', formData),

  listJobs: () =>
    fetchApi<AnalysisJob[]>('/traffic/jobs'),

  getJobStatus: (jobId: string) =>
    fetchApi<AnalysisJob>(`/traffic/jobs/${jobId}`),

  getJobResults: (jobId: string, limit = 100) =>
    fetchApi<NetworkFlow[]>(`/traffic/jobs/${jobId}/results?limit=${limit}`),

  getRecentFlows: (limit = 100, sourceType?: string) => {
    const url = sourceType ? `/traffic/flows?limit=${limit}&source_type=${sourceType}` : `/traffic/flows?limit=${limit}`;
    return fetchApi<NetworkFlow[]>(url);
  }
};
