import React, { useState } from 'react';
import { UploadCloud, FileText, Download, ShieldAlert, CheckCircle, BarChart3, AlertTriangle, Layers, Radio } from 'lucide-react';
import { trafficApi } from '../services/trafficApi';
import { StatCard } from '../components/common/StatCard';
import { RiskBadge, AttackBadge } from '../components/common/Badge';
import { AttackCategoryChart } from '../components/charts/AttackCategoryChart';
import { RiskDistributionChart } from '../components/charts/RiskDistributionChart';

export const BatchAnalysisPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploadFormat, setUploadFormat] = useState<'csv' | 'pcap'>('csv');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jobResult, setJobResult] = useState<any | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      if (selected.name.endsWith('.pcap') || selected.name.endsWith('.pcapng')) {
        setUploadFormat('pcap');
      } else if (selected.name.endsWith('.csv')) {
        setUploadFormat('csv');
      }
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);
    formData.append('dataset', selectedDataset);

    try {
      const res = await trafficApi.uploadTrafficFile(formData);
      setJobResult(res);
    } catch (err: any) {
      setError(err.message || 'Batch upload processing failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = (format: 'csv' | 'json') => {
    if (!jobResult || !jobResult.job_id) return;
    const downloadUrl = `http://localhost:8090/api/v1/traffic/jobs/${jobResult.job_id}/download?format=${format}`;
    window.open(downloadUrl, '_blank');
  };

  const summary = jobResult?.summary;
  const samplePredictions = jobResult?.sample_results || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-3">
            <UploadCloud className="h-6 w-6 text-cyan-400" />
            <h1 className="text-2xl font-bold text-slate-100 font-mono">BATCH NETWORK FLOW & PCAP ANALYSIS</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Upload CSV network flow captures or raw .pcap/.pcapng capture files for feature extraction, bulk inference, and threat classification.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-slate-800 p-1 rounded-xl border border-slate-700">
          <button
            onClick={() => setUploadFormat('csv')}
            className={`px-3 py-1.5 text-xs font-mono rounded-lg transition ${
              uploadFormat === 'csv' ? 'bg-cyan-600 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CSV Flow Format
          </button>
          <button
            onClick={() => setUploadFormat('pcap')}
            className={`px-3 py-1.5 text-xs font-mono rounded-lg transition ${
              uploadFormat === 'pcap' ? 'bg-cyan-600 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            PCAP / PCAPNG Raw
          </button>
        </div>
      </div>

      {/* Upload Dropzone */}
      <div className="cyber-card">
        <form onSubmit={handleUpload} className="space-y-4">
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-8 text-center bg-slate-900/40 transition flex flex-col items-center justify-center space-y-3">
            <UploadCloud className="w-12 h-12 text-cyan-400 animate-bounce" />
            <div>
              <p className="text-sm font-semibold text-slate-200 font-mono">
                {file ? file.name : `Select or Drop ${uploadFormat.toUpperCase()} Capture File`}
              </p>
              <p className="text-xs text-slate-400 mt-1">
                {uploadFormat === 'csv'
                  ? `CSV files containing flow features for ${selectedDataset.toUpperCase()} (Max: 50MB)`
                  : 'Packet capture files (.pcap, .pcapng) for flow extraction (Max: 50MB)'}
              </p>
            </div>
            <input
              type="file"
              accept={uploadFormat === 'csv' ? '.csv' : '.pcap,.pcapng'}
              onChange={handleFileChange}
              className="hidden"
              id="batch-file-input"
            />
            <label
              htmlFor="batch-file-input"
              className="cursor-pointer px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-xs font-mono font-medium rounded-lg transition"
            >
              Browse {uploadFormat.toUpperCase()} File
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
              {loading ? 'ANALYZING NETWORK CAPTURE...' : `PROCESS ${uploadFormat.toUpperCase()} ANALYSIS`}
            </button>
          </div>
        </form>
      </div>

      {/* Summary Section */}
      {summary && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 font-mono">Analysis Job: {jobResult.job_id}</h3>
              <p className="text-xs text-slate-400">Processed under model pipeline: {selectedDataset.toUpperCase()}</p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleDownload('csv')}
                className="flex items-center space-x-2 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono text-xs rounded-lg transition shadow-md shadow-emerald-950/40"
              >
                <Download className="w-3.5 h-3.5" />
                <span>EXPORT CSV</span>
              </button>
              <button
                onClick={() => handleDownload('json')}
                className="flex items-center space-x-2 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold font-mono text-xs rounded-lg transition shadow-md shadow-indigo-950/40"
              >
                <Download className="w-3.5 h-3.5" />
                <span>EXPORT JSON</span>
              </button>
            </div>
          </div>

          {/* Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              title="Total Flows Processed"
              value={summary.analyzed_rows || summary.analyzed_flows || 0}
              icon={FileText}
              color="indigo"
            />
            <StatCard
              title="Attacks Detected"
              value={summary.attack_count || 0}
              subtitle={`Benign: ${summary.benign_count || 0}`}
              icon={ShieldAlert}
              color="red"
            />
            <StatCard
              title="Attack Ratio"
              value={`${summary.attack_percentage || 0}%`}
              icon={BarChart3}
              color="amber"
            />
            <StatCard
              title="Average Risk Score"
              value={summary.average_risk_score || 0}
              subtitle="Calibrated 0-100"
              icon={AlertTriangle}
              color="cyan"
            />
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="cyber-card">
              <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Batch Attack Classification</h4>
              <AttackCategoryChart distribution={summary.category_distribution || {}} />
            </div>
            <div className="cyber-card">
              <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Batch Risk Distribution</h4>
              <RiskDistributionChart distribution={summary.risk_distribution || summary.risk_level_distribution || {}} />
            </div>
          </div>

          {/* Table */}
          <div className="cyber-card">
            <h4 className="text-xs font-semibold text-slate-200 font-mono mb-3">Sample Classified Flows</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#1F2937]/70 text-slate-400 uppercase tracking-wider">
                  <tr>
                    <th className="px-4 py-3">Flow / Endpoint</th>
                    <th className="px-4 py-3">Prediction</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Risk Level</th>
                    <th className="px-4 py-3">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {samplePredictions.map((pred: any) => (
                    <tr key={pred.flow_id || pred.prediction_id} className="hover:bg-slate-800/40">
                      <td className="px-4 py-3 text-slate-300">
                        {pred.src_ip ? `${pred.src_ip}:${pred.src_port} → ${pred.dst_ip}:${pred.dst_port}` : pred.prediction_id}
                      </td>
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
