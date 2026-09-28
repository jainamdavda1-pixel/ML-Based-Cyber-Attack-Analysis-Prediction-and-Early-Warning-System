import { fetchApi } from './api';
import { RiskCalculation, EarlyWarningMetrics } from '../types/risk';

export const riskApi = {
  calculateRisk: (benignProbability: number, dataset: string = 'cicids2017'): Promise<RiskCalculation> => {
    return fetchApi<RiskCalculation>('/risk', {
      method: 'POST',
      body: JSON.stringify({ benign_probability: benignProbability, dataset }),
    });
  },

  getEarlyWarningMetrics: (): Promise<EarlyWarningMetrics> => {
    return fetchApi<EarlyWarningMetrics>('/risk/early-warning');
  }
};
