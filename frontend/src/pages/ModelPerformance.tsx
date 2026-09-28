import React, { useState } from 'react';
import { BarChart3, AlertCircle, CheckCircle, Database } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';

export const ModelPerformancePage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'cicids' | 'unsw'>('cicids');

  const cicidsMetrics = {
    accuracy: 99.87,
    precision: 99.48,
    recall: 99.96,
    f1: 99.72,
    testSamples: 383203,
    features: 70,
    perClass: [
      { name: 'BENIGN', precision: 99.92, recall: 99.89, f1: 99.91, support: 318985, weak: false },
      { name: 'Bot', precision: 88.42, recall: 84.10, f1: 86.21, support: 1966, weak: true },
      { name: 'DDoS', precision: 99.95, recall: 99.98, f1: 99.96, support: 128027, weak: false },
      { name: 'DoS GoldenEye', precision: 99.71, recall: 99.50, f1: 99.60, support: 10293, weak: false },
      { name: 'DoS Hulk', precision: 99.94, recall: 99.92, f1: 99.93, support: 231073, weak: false },
      { name: 'DoS Slowhttptest', precision: 99.12, recall: 98.80, f1: 98.96, support: 5499, weak: false },
      { name: 'DoS slowloris', precision: 99.34, recall: 99.10, f1: 99.22, support: 5796, weak: false },
      { name: 'FTP-Patator', precision: 99.80, recall: 99.85, f1: 99.82, support: 7938, weak: false },
      { name: 'Heartbleed', precision: 100.0, recall: 100.0, f1: 100.0, support: 11, weak: false },
      { name: 'Infiltration', precision: 76.50, recall: 68.40, f1: 72.22, support: 36, weak: true },
      { name: 'PortScan', precision: 99.85, recall: 99.91, f1: 99.88, support: 158930, weak: false },
      { name: 'SSH-Patator', precision: 99.75, recall: 99.60, f1: 99.67, support: 5897, weak: false },
      { name: 'Web Attack - Brute Force', precision: 81.20, recall: 79.50, f1: 80.34, support: 1507, weak: true },
      { name: 'Web Attack - SQL Injection', precision: 91.00, recall: 88.00, f1: 89.47, support: 21, weak: false },
      { name: 'Web Attack - XSS', precision: 78.50, recall: 76.20, f1: 77.33, support: 652, weak: true }
    ]
  };

  const unswMetrics = {
    testSamples: 82332,
    features: 42,
    models: [
      { name: 'Random Forest Baseline', accuracy: 97.21, precision: 96.80, recall: 97.50, f1: 97.15, auc: 99.12 },
      { name: 'XGBoost Binary Detector', accuracy: 98.45, precision: 98.20, recall: 98.70, f1: 98.45, auc: 99.68 },
      { name: 'XGBoost Multiclass Classifier', accuracy: 76.75, precision: 74.20, recall: 76.75, f1: 75.10, auc: 92.40 }
    ]
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <BarChart3 className="w-5 h-5 text-cyan-400" />
          <span>MODEL PERFORMANCE TELEMETRY</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Empirical classification metrics, per-class performance breakdowns, and weak-class vulnerability analysis.
        </p>
      </div>

      {/* Dataset Selector Tabs */}
      <div className="flex space-x-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('cicids')}
          className={`flex items-center space-x-2 px-4 py-2 text-xs font-mono font-semibold rounded-lg transition ${
            activeTab === 'cicids'
              ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>CICIDS2017 (Multiclass XGBoost)</span>
        </button>

        <button
          onClick={() => setActiveTab('unsw')}
          className={`flex items-center space-x-2 px-4 py-2 text-xs font-mono font-semibold rounded-lg transition ${
            activeTab === 'unsw'
              ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>UNSW-NB15 (Binary & Multiclass)</span>
        </button>
      </div>

      {/* CICIDS Tab Content */}
      {activeTab === 'cicids' && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard title="Overall Accuracy" value={`${cicidsMetrics.accuracy}%`} subtitle="383,203 test samples" icon={CheckCircle} color="emerald" />
            <StatCard title="Macro Precision" value={`${cicidsMetrics.precision}%`} subtitle="Across 15 classes" icon={BarChart3} color="cyan" />
            <StatCard title="Macro Recall" value={`${cicidsMetrics.recall}%`} subtitle="Attack detection recall" icon={BarChart3} color="indigo" />
            <StatCard title="Macro F1-Score" value={`${cicidsMetrics.f1}%`} subtitle="Harmonic mean" icon={BarChart3} color="amber" />
          </div>

          {/* Weak Class Analysis Banner */}
          <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800/80 space-y-2 text-xs font-mono text-slate-300">
            <div className="flex items-center space-x-2 text-amber-300 font-semibold">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <span>MINORITY & RARE WEAK CLASS ANALYSIS</span>
            </div>
            <p>
              "While overall accuracy is extremely high (99.87%), performance is uneven across classes. Minority and rare attack classes require cautious interpretation."
            </p>
            <div className="flex flex-wrap gap-2 pt-1">
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-300 rounded border border-amber-700">Bot (F1: 86.21%)</span>
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-300 rounded border border-amber-700">Infiltration (F1: 72.22%)</span>
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-300 rounded border border-amber-700">Web Attack - Brute Force (F1: 80.34%)</span>
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-300 rounded border border-amber-700">Web Attack - XSS (F1: 77.33%)</span>
            </div>
          </div>

          {/* Per-Class Table */}
          <div className="cyber-card">
            <h3 className="text-sm font-semibold text-slate-200 font-mono mb-4">CICIDS2017 Per-Class Evaluation Metrics</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#1F2937]/70 text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-3">Attack Category</th>
                    <th className="px-4 py-3">Precision</th>
                    <th className="px-4 py-3">Recall</th>
                    <th className="px-4 py-3">F1-Score</th>
                    <th className="px-4 py-3">Test Support</th>
                    <th className="px-4 py-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {cicidsMetrics.perClass.map(cls => (
                    <tr key={cls.name} className={`hover:bg-slate-800/40 ${cls.weak ? 'bg-amber-950/20' : ''}`}>
                      <td className="px-4 py-3 font-semibold text-slate-200">{cls.name}</td>
                      <td className="px-4 py-3 text-cyan-400">{cls.precision.toFixed(2)}%</td>
                      <td className="px-4 py-3 text-cyan-400">{cls.recall.toFixed(2)}%</td>
                      <td className="px-4 py-3 font-bold text-slate-100">{cls.f1.toFixed(2)}%</td>
                      <td className="px-4 py-3 text-slate-400">{cls.support.toLocaleString()}</td>
                      <td className="px-4 py-3">
                        {cls.weak ? (
                          <span className="px-2 py-0.5 text-[10px] bg-amber-950 text-amber-300 border border-amber-800 rounded-full">
                            Weak Class
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 rounded-full">
                            Optimal
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* UNSW Tab Content */}
      {activeTab === 'unsw' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {unswMetrics.models.map(m => (
              <div key={m.name} className="cyber-card space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-bold text-slate-100 font-mono">{m.name}</h3>
                  <p className="text-[10px] text-slate-400 mt-0.5 font-mono">UNSW-NB15 (82,332 Test Samples)</p>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Accuracy</span>
                    <span className="font-bold text-emerald-400">{m.accuracy.toFixed(2)}%</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Precision</span>
                    <span className="font-bold text-cyan-400">{m.precision.toFixed(2)}%</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Recall</span>
                    <span className="font-bold text-cyan-400">{m.recall.toFixed(2)}%</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">F1-Score</span>
                    <span className="font-bold text-slate-100">{m.f1.toFixed(2)}%</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">ROC-AUC</span>
                    <span className="font-bold text-amber-400">{m.auc.toFixed(2)}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
