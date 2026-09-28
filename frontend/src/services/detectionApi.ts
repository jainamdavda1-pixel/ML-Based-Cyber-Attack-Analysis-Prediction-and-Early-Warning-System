import { fetchApi, uploadFileApi } from './api';
import { PredictionResult, BatchSummary, ModelDatasetInfo } from '../types/detection';

export const detectionApi = {
  predictSingle: (dataset: string, features: Record<string, number>): Promise<PredictionResult> => {
    return fetchApi<PredictionResult>('/predict', {
      method: 'POST',
      body: JSON.stringify({ dataset, features }),
    });
  },

  predictBatch: (dataset: string, file: File): Promise<BatchSummary> => {
    const formData = new FormData();
    formData.append('dataset', dataset);
    formData.append('file', file);
    return uploadFileApi<BatchSummary>('/predict/batch', formData);
  },

  getAvailableModels: (): Promise<{ datasets: ModelDatasetInfo[] }> => {
    return fetchApi<{ datasets: ModelDatasetInfo[] }>('/models');
  },

  getExplainability: (dataset: string) => {
    return fetchApi<{
      dataset: string;
      disclaimer: string;
      top_global_features: Array<{ feature: string; mean_shap_value: number; description: string }>;
      known_misclassifications: Array<{ pattern: string; direction: string; cause: string; details: string[] }>;
    }>(`/explain?dataset=${dataset}`);
  },

  getModelMetrics: (dataset?: string) => {
    const query = dataset ? `?dataset=${dataset}` : '';
    return fetchApi<any>(`/metrics${query}`);
  }
};
