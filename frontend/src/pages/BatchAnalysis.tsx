import React, { useState } from 'react';
import { UploadCloud, FileText, Download, ShieldAlert, CheckCircle, BarChart3, AlertTriangle } from 'lucide-react';
import { detectionApi } from '../services/detectionApi';
import { BatchSummary } from '../types/detection';
import { StatCard } from '../components/common/StatCard';
import { RiskBadge, AttackBadge } from '../components/common/Badge';
import { AttackCategoryChart } from '../components/charts/AttackCategoryChart';
import { RiskDistributionChart } from '../components/charts/RiskDistributionChart';

export const BatchAnalysisPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<BatchSummary | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);
    try {
      const res = await detectionApi.predictBatch(selectedDataset, file);
      setSummary(res);
    } catch (err: any) {
      setError(err.message || 'Batch upload processing failed');
    } finally {
      setLoading(false);
    }
  };

  const downloadCSV = () => {
    if (!summary || !summary.sample_predictions) return;
    const headers = ['Prediction ID', 'Dataset', 'Prediction', 'Is Attack', 'Attack Probability', 'Confidence', 'Risk Score', 'Risk Level'];
    const rows = summary.sample_predictions.map(p => [
      p.prediction_id,
      p.dataset,
      p.prediction,
      p.is_attack,
      p.attack_probability,
      p.confidence,
      p.risk_score,
      p.risk_level
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `batch_predictions_${selectedDataset}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <UploadCloud className="w-5 h-5 text-cyan-400" />
          <span>BATCH NETWORK FLOW ANALYSIS</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Upload a network traffic CSV capture file to evaluate bulk flow records, generate threat distribution stats, and export prediction CSVs.
        </p>
      </div>

      {/* Upload Dropzone */}
      <div className="cyber-card">
        <form onSubmit={handleUpload} className="space-y-4">
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-8 text-center bg-slate-900/40 transition flex flex-col items-center justify-center space-y-3">
            <UploadCloud className="w-12 h-12 text-cyan-400 animate-bounce" />
            <div>
              <p className="text-sm font-semibold text-slate-200 font-mono">
                {file ? file.name : 'Select or Drop Network Capture CSV File'}
              </p>
              <p className="text-xs text-slate-400 mt-1">
                CSV files containing flow features for {selectedDataset.toUpperCase()} (Max size: 20MB)
              </p>
            </div>
            <input
              type="file"
              accept=".csv"
              onChange={handleFileChange}
              className="hidden"
              id="batch-file-input"
            />
            <label
              htmlFor="batch-file-input"
              className="cursor-pointer px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-xs font-mono font-medium rounded-lg transition"
            >
              Browse CSV Files
            </label>
          </div>

          {error && (
            <div className="p-3 bg-red-950/60 border border-red-800 text-red-300 text-xs rounded-lg font-mono">
              {error}
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={!file || loading}
              className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold font-mono text-xs rounded-lg transition shadow-lg shadow-cyan-950/40"
            >
              {loading ? 'PROCESSING BATCH CSV...' : 'PROCESS BATCH ANALYSIS'}
            </button>
          </div>
        </form>
      </div>

      {/* Summary Section */}
      {summary && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-slate-100 font-mono">Batch Telemetry Summary</h3>
            <button
              onClick={downloadCSV}
              className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono text-xs rounded-lg transition shadow-lg shadow-emerald-950/40"
            >
              <Download className="w-4 h-4" />
              <span>DOWNLOAD PREDICTION RESULTS CSV</span>
            </button>
          </div>

          {/* Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard title="Total Flows Processed" value={summary.total_records} icon={FileText} color="indigo" />
            <StatCard title="Attacks Detected" value={summary.attack_count} subtitle={`Benign: ${summary.benign_count}`} icon={ShieldAlert} color="red" />
            <StatCard title="Attack Ratio" value={`${summary.attack_percentage}%`} icon={BarChart3} color="amber" />
            <StatCard title="Critical/High Risks" value={summary.critical_risk_count + summary.high_risk_count} icon={AlertTriangle} color="cyan" />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="cyber-card">
              <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Batch Attack Classification</h4>
              <AttackCategoryChart distribution={summary.category_distribution} />
            </div>
            <div className="cyber-card">
              <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Batch Risk Distribution</h4>
              <RiskDistributionChart distribution={summary.risk_level_distribution} />
            </div>
          </div>

          {/* Table */}
          <div className="cyber-card">
            <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Sample Flow Records</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#1F2937]/70 text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Prediction</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Risk Level</th>
                    <th className="px-4 py-3">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {summary.sample_predictions.map(pred => (
                    <tr key={pred.prediction_id} className="hover:bg-slate-800/40">
                      <td className="px-4 py-3 text-slate-400">{pred.prediction_id}</td>
                      <td className="px-4 py-3 font-semibold text-slate-200">{pred.prediction}</td>
                      <td className="px-4 py-3">
                        <AttackBadge isAttack={pred.is_attack} prediction={pred.prediction} />
                      </td>
                      <td className="px-4 py-3 font-bold text-slate-300">{pred.risk_score}</td>
                      <td className="px-4 py-3">
                        <RiskBadge level={pred.risk_level} size="sm" />
                      </td>
                      <td className="px-4 py-3 text-slate-300">{(pred.confidence * 100).toFixed(2)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
