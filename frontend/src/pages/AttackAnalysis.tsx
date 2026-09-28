import React, { useEffect, useState } from 'react';
import { Cpu, HelpCircle, AlertCircle, Sparkles, Layers } from 'lucide-react';
import { detectionApi } from '../services/detectionApi';
import { SHAPBarChart } from '../components/charts/SHAPBarChart';

export const AttackAnalysisPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [data, setData] = useState<{
    dataset: string;
    disclaimer: string;
    top_global_features: Array<{ feature: string; mean_shap_value: number; description: string }>;
    known_misclassifications: Array<{ pattern: string; direction: string; cause: string; details: string[] }>;
  } | null>(null);

  useEffect(() => {
    detectionApi.getExplainability(selectedDataset).then(setData).catch(console.error);
  }, [selectedDataset]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-cyan-400" />
          <span>SHAP MODEL EXPLAINABILITY & MISCLASSIFICATION ANALYSIS</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Interpretable machine learning feature attributions using SHAP (SHapley Additive exPlanations) values.
        </p>
      </div>

      {/* Disclaimer Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-start space-x-3 text-xs text-slate-300">
        <Sparkles className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="space-y-1">
          <p className="font-semibold text-cyan-300 font-mono">EXPLAINABILITY TERMINOLOGY POLICY</p>
          <p>
            {data?.disclaimer || 'Features displayed represent mathematical feature attributions calculated by SHAP TreeExplainer. SHAP values indicate features that contributed strongly to a prediction, not causal proof of an attack.'}
          </p>
        </div>
      </div>

      {/* Global SHAP Feature Importances Chart */}
      <div className="cyber-card">
        <div className="flex justify-between items-center mb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Top 10 Global SHAP Feature Attributions ({selectedDataset.toUpperCase()})</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Mean absolute SHAP value impact across overall test dataset evaluation
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-3 py-1 rounded-full border border-cyan-800">
            TreeExplainer
          </span>
        </div>

        {data?.top_global_features && <SHAPBarChart data={data.top_global_features} />}

        {/* Feature Descriptions Grid */}
        <div className="mt-6 pt-4 border-t border-slate-800">
          <h4 className="text-xs font-semibold text-slate-300 font-mono mb-3">Feature Descriptions & Roles</h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
            {data?.top_global_features.map((item, idx) => (
              <div key={item.feature} className="p-3 bg-slate-900/60 border border-slate-800/80 rounded-lg flex items-start space-x-3">
                <span className="w-5 h-5 rounded bg-cyan-950 text-cyan-400 flex items-center justify-center font-bold text-[10px] flex-shrink-0">
                  {idx + 1}
                </span>
                <div>
                  <span className="font-semibold text-slate-200 block">{item.feature}</span>
                  <span className="text-slate-400 text-[11px] block mt-0.5">{item.description}</span>
                  <span className="text-[10px] text-cyan-400 mt-1 block">Mean SHAP: {item.mean_shap_value}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Known Misclassification Patterns Section */}
      <div className="cyber-card space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-amber-400" />
            <span>Known Model Misclassification Patterns</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Empirical feature attributions explaining decision confusion boundaries observed in model evaluation
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Pattern 1 */}
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <div className="flex justify-between items-start">
              <span className="text-xs font-bold font-mono text-amber-400">XSS ↔ Web Attack - Brute Force Overlap</span>
              <span className="text-[10px] font-mono bg-amber-950 text-amber-300 px-2 py-0.5 rounded border border-amber-800">
                Web Attack Confusion
              </span>
            </div>
            <p className="text-xs text-slate-300">
              For <span className="font-mono text-slate-100 font-semibold">Brute Force → XSS</span> classification errors:
            </p>
            <ul className="text-xs text-slate-400 space-y-1.5 font-mono list-disc list-inside">
              <li><strong className="text-slate-200">Init_Win_bytes_backward</strong> strongly favored Brute Force.</li>
              <li><strong className="text-slate-200">Max Packet Length</strong> and <strong className="text-slate-200">Bwd Header Length</strong> strongly favored XSS.</li>
              <li>Several IAT-related features contributed to the feature space overlap between HTTP request streams.</li>
            </ul>
          </div>

          {/* Pattern 2 */}
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
            <div className="flex justify-between items-start">
              <span className="text-xs font-bold font-mono text-cyan-400">BENIGN → Bot False Positives</span>
              <span className="text-[10px] font-mono bg-cyan-950 text-cyan-300 px-2 py-0.5 rounded border border-cyan-800">
                Background Traffic Confusion
              </span>
            </div>
            <p className="text-xs text-slate-300">
              For <span className="font-mono text-slate-100 font-semibold">BENIGN → Bot</span> false positive alerts:
            </p>
            <ul className="text-xs text-slate-400 space-y-1.5 font-mono list-disc list-inside">
              <li><strong className="text-slate-200">Destination Port</strong> was the strongest differentiating feature.</li>
              <li>Periodic automated background tasks on workstations mimic C2 heartbeat packet intervals.</li>
              <li>Flow duration and packet count ratios triggered Bot classifier thresholds.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
