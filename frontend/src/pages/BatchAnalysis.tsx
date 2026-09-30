import React, { useState, useMemo } from 'react';
import {
  UploadCloud, FileText, Download, ShieldAlert, CheckCircle, BarChart3,
  AlertTriangle, Layers, CheckCircle2, XCircle, Info, Database,
  PieChart, Activity, Search, RefreshCw, Cpu, HelpCircle, ArrowRight
} from 'lucide-react';
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

  // Active Tab state for result view
  const [activeTab, setActiveTab] = useState<'threats' | 'profiling' | 'compatibility'>('threats');
  
  // Search filters for tables
  const [evidenceSearch, setEvidenceSearch] = useState('');
  const [featureStatSearch, setFeatureStatSearch] = useState('');
  const [mappingSearch, setMappingSearch] = useState('');

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
      setActiveTab('threats'); // reset to primary tab
    } catch (err: any) {
      setError(err.message || 'Batch upload processing failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setJobResult(null);
    setError(null);
  };

  const handleDownload = (format: 'csv' | 'json') => {
    if (!jobResult || !jobResult.job_id) return;
    const downloadUrl = `http://localhost:8090/api/v1/traffic/jobs/${jobResult.job_id}/download?format=${format}`;
    window.open(downloadUrl, '_blank');
  };

  const summary = jobResult?.summary;
  const isEvaluationOnly = jobResult?.evaluation_mode === 'DATASET_EVALUATION_ONLY' || summary?.evaluation_mode === 'DATASET_EVALUATION_ONLY';
  const compatibility = summary?.compatibility_profile;
  const samplePredictions = jobResult?.sample_results || [];
  const datasetEval = summary?.dataset_evaluation || (isEvaluationOnly ? summary : null);
  const threatAnalysis = datasetEval?.potential_threat_analysis;

  // Filtered lists for tables
  const filteredEvidence = useMemo(() => {
    if (!threatAnalysis?.record_level_evidence) return [];
    if (!evidenceSearch.trim()) return threatAnalysis.record_level_evidence;
    const q = evidenceSearch.toLowerCase();
    return threatAnalysis.record_level_evidence.filter((ev: any) =>
      (ev.actual_label && ev.actual_label.toLowerCase().includes(q)) ||
      (ev.evidence_details && ev.evidence_details.toLowerCase().includes(q)) ||
      (ev.potential_indicators && ev.potential_indicators.some((ind: string) => ind.toLowerCase().includes(q))) ||
      `#${ev.row_index + 1}`.includes(q)
    );
  }, [threatAnalysis, evidenceSearch]);

  const filteredFeatureStats = useMemo(() => {
    if (!datasetEval?.sample_feature_statistics) return [];
    const entries = Object.entries(datasetEval.sample_feature_statistics);
    if (!featureStatSearch.trim()) return entries;
    const q = featureStatSearch.toLowerCase();
    return entries.filter(([feat]) => feat.toLowerCase().includes(q));
  }, [datasetEval, featureStatSearch]);

  const filteredMappings = useMemo(() => {
    if (!compatibility?.mapping_report) return [];
    if (!mappingSearch.trim()) return compatibility.mapping_report;
    const q = mappingSearch.toLowerCase();
    return compatibility.mapping_report.filter((m: any) =>
      (m.target_feature && m.target_feature.toLowerCase().includes(q)) ||
      (m.source_feature && m.source_feature.toLowerCase().includes(q)) ||
      (m.transform_type && m.transform_type.toLowerCase().includes(q)) ||
      (m.status && m.status.toLowerCase().includes(q))
    );
  }, [compatibility, mappingSearch]);

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-12">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/70 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 rounded-xl border border-cyan-500/20">
              <UploadCloud className="h-6 w-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-wide">
                BATCH TRAFFIC & CAPTURE ANALYSIS
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Upload CSV network flow captures or raw PCAP/PCAPNG packet traces for automatic adaptation and deep security analysis.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-slate-800/80 p-1.5 rounded-xl border border-slate-700/80">
          <button
            onClick={() => setUploadFormat('csv')}
            className={`px-3.5 py-1.5 text-xs font-mono rounded-lg transition font-medium ${
              uploadFormat === 'csv'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-950/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CSV Flow Captures
          </button>
          <button
            onClick={() => setUploadFormat('pcap')}
            className={`px-3.5 py-1.5 text-xs font-mono rounded-lg transition font-medium ${
              uploadFormat === 'pcap'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-950/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            PCAP / PCAPNG Raw
          </button>
        </div>
      </div>

      {/* Upload Dropzone (when no result yet or user wants to re-upload) */}
      {!jobResult && (
        <div className="cyber-card p-8">
          <form onSubmit={handleUpload} className="space-y-6">
            <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/80 rounded-2xl p-10 text-center bg-slate-900/30 transition duration-200 flex flex-col items-center justify-center space-y-4">
              <div className="p-4 bg-cyan-500/10 rounded-2xl border border-cyan-500/20 text-cyan-400">
                <UploadCloud className="w-10 h-10" />
              </div>
              <div className="space-y-1">
                <p className="text-base font-semibold text-slate-200 font-mono">
                  {file ? file.name : `Select or Drag & Drop ${uploadFormat.toUpperCase()} Capture File`}
                </p>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  {uploadFormat === 'csv'
                    ? `Upload network flow telemetry in CSV format. Schema adaptation and validation will execute automatically.`
                    : 'Upload raw .pcap or .pcapng files. Canonical bidirectional flow aggregation will extract network flow records.'}
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
                className="cursor-pointer px-5 py-2.5 bg-slate-800 hover:bg-slate-700/90 text-cyan-300 border border-slate-700 text-xs font-mono font-bold rounded-xl transition shadow-sm"
              >
                {file ? 'Change Selected File' : `Browse ${uploadFormat.toUpperCase()} File`}
              </label>
            </div>

            {error && (
              <div className="p-4 bg-red-950/50 border border-red-800/80 text-red-300 text-xs rounded-xl font-mono flex items-start gap-3">
                <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-bold text-red-200">Analysis Processing Failed</div>
                  <div className="text-red-300/90">{error}</div>
                </div>
              </div>
            )}

            <div className="flex justify-between items-center pt-2">
              <div className="text-xs text-slate-400 font-mono">
                Target Model Pipeline: <span className="text-cyan-400 font-bold">{selectedDataset.toUpperCase()}</span>
              </div>
              <button
                type="submit"
                disabled={!file || loading}
                className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-slate-950 font-bold font-mono text-xs rounded-xl transition shadow-lg shadow-cyan-950/40 flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>ANALYZING DATASET...</span>
                  </>
                ) : (
                  <>
                    <span>START {uploadFormat.toUpperCase()} ANALYSIS</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* RESULTS PRESENTATION SECTION */}
      {jobResult && (
        <div className="space-y-8 animate-fadeIn">
          {/* Result Header Bar */}
          <div className="bg-slate-900/90 rounded-2xl border border-slate-800 p-6 shadow-xl backdrop-blur-xl flex flex-col lg:flex-row justify-between items-start lg:items-center gap-6">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-xs font-mono font-bold text-slate-400">JOB ID:</span>
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/50 px-2.5 py-1 rounded-lg border border-cyan-800/50 font-bold">
                  {jobResult.job_id}
                </span>

                <span className={`px-3 py-1 rounded-lg text-xs font-mono font-bold border flex items-center gap-1.5 ${
                  !isEvaluationOnly
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                    : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                }`}>
                  {!isEvaluationOnly ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>MODEL INFERENCE ACTIVE</span>
                    </>
                  ) : (
                    <>
                      <Info className="w-3.5 h-3.5" />
                      <span>EVALUATION-ONLY ANALYSIS</span>
                    </>
                  )}
                </span>

                {compatibility?.status && (
                  <span className="text-xs font-mono px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
                    Schema: <strong className="text-slate-100">{compatibility.status}</strong>
                  </span>
                )}
              </div>

              <p className="text-xs text-slate-400">
                {!isEvaluationOnly
                  ? `Successfully validated and classified under trained XGBoost pipeline for ${selectedDataset.toUpperCase()}.`
                  : 'Incompatible with trained classifier inputs. Evaluated safely using explainable behavioral heuristics & statistical outlier detection.'}
              </p>
            </div>

            {/* Actions: Export & New Upload */}
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={() => handleDownload('csv')}
                className="flex items-center space-x-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold font-mono text-xs rounded-xl transition shadow-md shadow-emerald-950/40"
                title="Export detailed evidence rows as CSV"
              >
                <Download className="w-4 h-4" />
                <span>EXPORT CSV</span>
              </button>
              <button
                onClick={() => handleDownload('json')}
                className="flex items-center space-x-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold font-mono text-xs rounded-xl transition shadow-md shadow-indigo-950/40"
                title="Export complete analysis report as JSON"
              >
                <Download className="w-4 h-4" />
                <span>EXPORT JSON</span>
              </button>
              <button
                onClick={handleReset}
                className="flex items-center space-x-1.5 px-3 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs rounded-xl border border-slate-700 transition"
                title="Upload another capture file"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>NEW FILE</span>
              </button>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-slate-800 gap-2 font-mono text-xs">
            <button
              onClick={() => setActiveTab('threats')}
              className={`pb-3.5 px-4 font-bold transition-all relative flex items-center gap-2 ${
                activeTab === 'threats'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>{!isEvaluationOnly ? 'MODEL PREDICTIONS & ATTACKS' : 'POTENTIAL THREAT ANALYSIS'}</span>
              {isEvaluationOnly && threatAnalysis?.active_indicators_count > 0 && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {threatAnalysis.active_indicators_count}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab('profiling')}
              className={`pb-3.5 px-4 font-bold transition-all relative flex items-center gap-2 ${
                activeTab === 'profiling'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-4 h-4" />
              <span>DATASET PROFILING & STATISTICS</span>
            </button>

            <button
              onClick={() => setActiveTab('compatibility')}
              className={`pb-3.5 px-4 font-bold transition-all relative flex items-center gap-2 ${
                activeTab === 'compatibility'
                  ? 'text-cyan-400 border-b-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-4 h-4" />
              <span>COMPATIBILITY & SCHEMA ADAPTATION</span>
            </button>
          </div>

          {/* TAB 1: THREATS / PREDICTIONS */}
          {activeTab === 'threats' && (
            <div className="space-y-8 animate-fadeIn">
              {/* If Evaluation-Only: Explainable Threat Indicators & Anomaly Detection */}
              {isEvaluationOnly ? (
                <>
                  {/* High-Level Stat Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
                    <StatCard
                      title="Audited Records"
                      value={datasetEval?.total_records || 0}
                      icon={FileText}
                      color="indigo"
                    />
                    <StatCard
                      title="Active Threat Rules"
                      value={threatAnalysis?.active_indicators_count || 0}
                      subtitle="Explainable behavioral indicators"
                      icon={ShieldAlert}
                      color={threatAnalysis?.active_indicators_count > 0 ? "amber" : "emerald"}
                    />
                    <StatCard
                      title="Statistical Outlier %"
                      value={`${threatAnalysis?.anomaly_detector?.anomaly_percentage || 0}%`}
                      subtitle={`Outlier count: ${threatAnalysis?.anomaly_detector?.total_anomalies_detected || 0}`}
                      icon={Activity}
                      color="cyan"
                    />
                    <StatCard
                      title="Ground-Truth Annotation"
                      value={datasetEval?.has_ground_truth_labels ? 'Provided' : 'Unlabeled'}
                      subtitle={datasetEval?.detected_label_column ? `Column: ${datasetEval.detected_label_column}` : 'No label column'}
                      icon={PieChart}
                      color={datasetEval?.has_ground_truth_labels ? 'indigo' : 'cyan'}
                    />
                  </div>

                  {/* Explainable Behavioral Indicators Section */}
                  <div className="space-y-4">
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                      <div>
                        <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 text-amber-400" />
                          <span>EXPLAINABLE POTENTIAL THREAT INDICATORS</span>
                        </h3>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Deterministic heuristic rules derived from validated network traffic patterns. No simulated or fabricated ML probabilities.
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {threatAnalysis?.indicators?.map((ind: any) => (
                        <div
                          key={ind.indicator_id}
                          className={`p-6 rounded-2xl border transition-all duration-200 flex flex-col justify-between space-y-4 ${
                            ind.detected
                              ? 'bg-slate-900/90 border-amber-500/40 shadow-lg shadow-amber-950/20'
                              : 'bg-slate-900/40 border-slate-800/80 opacity-75'
                          }`}
                        >
                          {/* Header with Title and Badges */}
                          <div className="flex justify-between items-start gap-3">
                            <div className="space-y-1">
                              <h4 className="text-sm font-bold text-slate-200 font-mono tracking-wide">
                                {ind.name}
                              </h4>
                              <div className="text-[11px] text-slate-400 font-mono">
                                Category: <span className="text-slate-300 font-medium">{ind.category}</span>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span className={`px-2.5 py-1 text-[11px] font-mono font-bold rounded-lg ${
                                ind.severity === 'HIGH'
                                  ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                  : ind.severity === 'MEDIUM'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                  : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                              }`}>
                                {ind.severity}
                              </span>
                              <span className={`px-2.5 py-1 text-[11px] font-mono font-bold rounded-lg ${
                                ind.detected
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                              }`}>
                                {ind.detected ? 'TRIGGERED' : 'INACTIVE'}
                              </span>
                            </div>
                          </div>

                          {/* Evidence Summary Block */}
                          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2">
                            <div className="text-xs font-mono text-slate-300 leading-relaxed">
                              <span className="text-amber-400 font-bold">Observed Evidence: </span>
                              {ind.evidence_summary}
                            </div>
                            {ind.detected && (
                              <div className="flex items-center gap-2 pt-1 border-t border-slate-800/60 text-xs font-mono text-cyan-300">
                                <span className="text-slate-400">Affected Records:</span>
                                <strong className="text-cyan-200">{ind.affected_records_count.toLocaleString()} rows</strong>
                                <span className="text-slate-500">({ind.affected_percentage}% of capture)</span>
                              </div>
                            )}
                          </div>

                          {/* Methodology and Limitations Spacing */}
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs font-mono border-t border-slate-800/60">
                            <div className="space-y-1">
                              <span className="text-slate-400 font-semibold text-[11px]">Detection Logic:</span>
                              <p className="text-slate-300 text-[11px] leading-normal">{ind.detection_method}</p>
                            </div>
                            <div className="space-y-1">
                              <span className="text-slate-500 font-semibold text-[11px]">Evaluation Limitations:</span>
                              <p className="text-slate-400 text-[11px] leading-normal">{ind.limitations}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Unsupervised Anomaly Detector Card */}
                  {threatAnalysis?.anomaly_detector && (
                    <div className="cyber-card space-y-4 border-l-4 border-l-cyan-500">
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-3 border-b border-slate-800">
                        <div className="space-y-1">
                          <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyan-400" />
                            <span>UNSUPERVISED STATISTICAL OUTLIER DETECTION (ISOLATION FOREST)</span>
                          </h4>
                          <p className="text-xs text-slate-400">
                            Multi-dimensional density analysis identifying atypical flow features without relying on labeled signatures.
                          </p>
                        </div>
                        <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                          {threatAnalysis.anomaly_detector.status}
                        </span>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
                        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                          <span className="text-slate-400 text-xs">Detected Statistical Outliers:</span>
                          <div className="text-lg font-bold text-cyan-300 mt-1">
                            {threatAnalysis.anomaly_detector.total_anomalies_detected} records
                            <span className="text-xs font-normal text-slate-400 ml-2">
                              ({threatAnalysis.anomaly_detector.anomaly_percentage}%)
                            </span>
                          </div>
                        </div>
                        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                          <span className="text-slate-400 text-xs">Feature Dimensions Evaluated:</span>
                          <div className="text-lg font-bold text-slate-200 mt-1">
                            {threatAnalysis.anomaly_detector.features_used?.length || 0} numeric features
                          </div>
                        </div>
                        <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                          <span className="text-slate-400 text-xs">Model Assumptions & Scope:</span>
                          <div className="text-xs text-slate-300 mt-1 line-clamp-2" title={threatAnalysis.anomaly_detector.limitations}>
                            {threatAnalysis.anomaly_detector.limitations}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Record-Level Evidence Table */}
                  {threatAnalysis?.record_level_evidence && threatAnalysis.record_level_evidence.length > 0 && (
                    <div className="cyber-card space-y-4">
                      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-2 border-b border-slate-800">
                        <div>
                          <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                            <Layers className="w-4 h-4 text-cyan-400" />
                            <span>RECORD-LEVEL THREAT EVIDENCE & AUDIT LOG</span>
                          </h4>
                          <p className="text-xs text-slate-400 mt-0.5">
                            Traceable row-by-row evidence for flows triggering suspicious behavioral rules or outlier thresholds.
                          </p>
                        </div>
                        <div className="flex items-center gap-3 w-full sm:w-auto">
                          <div className="relative w-full sm:w-64">
                            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                            <input
                              type="text"
                              value={evidenceSearch}
                              onChange={(e) => setEvidenceSearch(e.target.value)}
                              placeholder="Filter evidence or label..."
                              className="cyber-input text-xs pl-8 py-1.5 w-full"
                            />
                          </div>
                          <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
                            Showing {filteredEvidence.length} rows
                          </span>
                        </div>
                      </div>

                      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-[#1F2937]/90 text-slate-300 uppercase tracking-wider sticky top-0">
                            <tr>
                              <th className="px-4 py-3">Row Index</th>
                              <th className="px-4 py-3">Actual Dataset Label</th>
                              <th className="px-4 py-3">Triggered Threat Indicators</th>
                              <th className="px-4 py-3 text-center">Outlier Index</th>
                              <th className="px-4 py-3">Behavioral Evidence Details</th>
                              <th className="px-4 py-3">Key Sample Features</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/80">
                            {filteredEvidence.length === 0 ? (
                              <tr>
                                <td colSpan={6} className="px-4 py-8 text-center text-slate-400">
                                  No evidence records match the search filter.
                                </td>
                              </tr>
                            ) : (
                              filteredEvidence.map((ev: any) => (
                                <tr key={ev.row_index} className="hover:bg-slate-800/30 transition">
                                  <td className="px-4 py-3 text-cyan-400 font-bold">
                                    #{ev.row_index + 1}
                                  </td>
                                  <td className="px-4 py-3">
                                    {ev.actual_label ? (
                                      <span className="px-2.5 py-1 rounded text-[11px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                                        {ev.actual_label}
                                      </span>
                                    ) : (
                                      <span className="text-slate-500 italic">Unlabeled</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3">
                                    <div className="flex flex-wrap gap-1.5">
                                      {ev.potential_indicators?.map((indName: string, i: number) => (
                                        <span
                                          key={i}
                                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                            indName.includes('DoS') || indName.includes('Burst')
                                              ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                                              : indName.includes('Scan') || indName.includes('Probe')
                                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                              : indName.includes('Outlier')
                                              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                                          }`}
                                        >
                                          {indName}
                                        </span>
                                      ))}
                                    </div>
                                  </td>
                                  <td className="px-4 py-3 text-center">
                                    {ev.statistical_outlier_score ? (
                                      <span className={`px-2 py-0.5 rounded font-bold text-xs ${
                                        ev.statistical_outlier_score >= 80
                                          ? 'text-red-400 bg-red-950/40'
                                          : ev.statistical_outlier_score >= 60
                                          ? 'text-amber-400 bg-amber-950/40'
                                          : 'text-cyan-400 bg-cyan-950/40'
                                      }`}>
                                        {ev.statistical_outlier_score} / 100
                                      </span>
                                    ) : (
                                      <span className="text-slate-600">—</span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3 text-slate-300 max-w-sm text-xs leading-normal">
                                    {ev.evidence_details}
                                  </td>
                                  <td className="px-4 py-3 text-slate-400 text-[11px] font-mono">
                                    {ev.key_features
                                      ? Object.entries(ev.key_features)
                                          .map(([k, v]) => `${k}=${v}`)
                                          .join(', ')
                                      : '—'}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                /* When Model Inference is Active: Standard Supervised ML View */
                <>
                  {/* ML Stat Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
                    <StatCard
                      title="Total Flows Classified"
                      value={summary?.analyzed_rows || summary?.analyzed_flows || 0}
                      icon={FileText}
                      color="indigo"
                    />
                    <StatCard
                      title="Attacks Detected"
                      value={summary?.attack_count || 0}
                      subtitle={`Benign: ${summary?.benign_count || 0}`}
                      icon={ShieldAlert}
                      color="red"
                    />
                    <StatCard
                      title="Attack Ratio"
                      value={`${summary?.attack_percentage || 0}%`}
                      icon={BarChart3}
                      color="amber"
                    />
                    <StatCard
                      title="Average Risk Score"
                      value={summary?.average_risk_score || 0}
                      subtitle="Calibrated 0-100"
                      icon={AlertTriangle}
                      color="cyan"
                    />
                  </div>

                  {/* Classification Charts */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="cyber-card">
                      <h4 className="text-xs font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
                        <PieChart className="w-4 h-4 text-cyan-400" />
                        <span>ATTACK CATEGORY CLASSIFICATION</span>
                      </h4>
                      <AttackCategoryChart distribution={summary?.category_distribution || {}} />
                    </div>
                    <div className="cyber-card">
                      <h4 className="text-xs font-bold text-slate-200 font-mono mb-4 flex items-center gap-2">
                        <BarChart3 className="w-4 h-4 text-amber-400" />
                        <span>RISK LEVEL DISTRIBUTION</span>
                      </h4>
                      <RiskDistributionChart distribution={summary?.risk_distribution || summary?.risk_level_distribution || {}} />
                    </div>
                  </div>

                  {/* Sample Classified Flows Table */}
                  <div className="cyber-card space-y-4">
                    <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyan-400" />
                      <span>CLASSIFIED NETWORK FLOWS (TRACEABLE SAMPLE)</span>
                    </h4>
                    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-[#1F2937]/90 text-slate-300 uppercase tracking-wider sticky top-0">
                          <tr>
                            <th className="px-4 py-3">Row Index</th>
                            <th className="px-4 py-3">Flow Endpoint Connection</th>
                            <th className="px-4 py-3">Model Prediction</th>
                            <th className="px-4 py-3">Verdict</th>
                            <th className="px-4 py-3">Risk Score</th>
                            <th className="px-4 py-3">Risk Level</th>
                            <th className="px-4 py-3">Confidence</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/80">
                          {samplePredictions.map((pred: any) => (
                            <tr key={pred.flow_id || pred.prediction_id} className="hover:bg-slate-800/30 transition">
                              <td className="px-4 py-3 text-cyan-400 font-bold">
                                {pred.row_index !== undefined ? `#${pred.row_index + 1}` : pred.flow_id?.slice(0, 10)}
                              </td>
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
                </>
              )}
            </div>
          )}

          {/* TAB 2: PROFILING & STATISTICS */}
          {activeTab === 'profiling' && (
            <div className="space-y-8 animate-fadeIn">
              {/* Actual Pre-Existing Dataset Labels (if provided in file) */}
              {datasetEval?.has_ground_truth_labels && datasetEval.label_distribution ? (
                <div className="cyber-card space-y-4 border-l-4 border-l-indigo-500">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                        <PieChart className="w-4 h-4 text-indigo-400" />
                        <span>ACTUAL GROUND-TRUTH DATASET LABELS (Column: {datasetEval.detected_label_column})</span>
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {datasetEval.ground_truth_disclaimer || 'Pre-existing labels in dataset. These are annotations, NOT model inference predictions.'}
                      </p>
                    </div>
                    {datasetEval.class_imbalance_ratio && (
                      <span className="text-xs font-mono text-indigo-300 bg-indigo-950/60 px-3 py-1 rounded-lg border border-indigo-800 font-semibold">
                        Imbalance Ratio: {datasetEval.class_imbalance_ratio}:1
                      </span>
                    )}
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 pt-1 font-mono text-xs">
                    {Object.entries(datasetEval.label_distribution).map(([lbl, count]) => (
                      <div key={lbl} className="bg-slate-900/80 p-4 rounded-xl border border-slate-800 flex justify-between items-center">
                        <span className="text-slate-300 font-semibold truncate mr-2" title={lbl}>{lbl}</span>
                        <span className="text-indigo-300 font-bold text-sm">{Number(count).toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="cyber-card p-6 bg-slate-900/40 border-slate-800 flex items-center gap-4 text-slate-400 font-mono text-xs">
                  <Info className="w-5 h-5 text-slate-500 flex-shrink-0" />
                  <div>
                    <span className="font-bold text-slate-300">Unlabeled Dataset: </span>
                    No ground-truth target columns (e.g. `Label`, `attack_cat`) were found in this file. Analyzed in pure unsupervised / heuristic evaluation mode.
                  </div>
                </div>
              )}

              {/* Data Quality & Integrity Profiling */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
                <div className="cyber-card p-5 space-y-2">
                  <span className="text-slate-400 font-mono text-xs">Total Records Profiled:</span>
                  <div className="text-2xl font-bold font-mono text-slate-100">
                    {(datasetEval?.total_records || summary?.analyzed_rows || 0).toLocaleString()}
                  </div>
                  <p className="text-[11px] text-slate-500 font-mono">Total rows parsed from uploaded file</p>
                </div>

                <div className="cyber-card p-5 space-y-2">
                  <span className="text-slate-400 font-mono text-xs">Missing Values Ratio:</span>
                  <div className={`text-2xl font-bold font-mono ${
                    (datasetEval?.missing_percentage || 0) > 5 ? 'text-red-400' : 'text-emerald-400'
                  }`}>
                    {datasetEval?.missing_percentage || 0}%
                  </div>
                  <p className="text-[11px] text-slate-500 font-mono">Null or NaN cells across numeric features</p>
                </div>

                <div className="cyber-card p-5 space-y-2">
                  <span className="text-slate-400 font-mono text-xs">Duplicate Rows Ratio:</span>
                  <div className={`text-2xl font-bold font-mono ${
                    (datasetEval?.duplicate_percentage || 0) > 10 ? 'text-amber-400' : 'text-slate-200'
                  }`}>
                    {datasetEval?.duplicate_percentage || 0}%
                  </div>
                  <p className="text-[11px] text-slate-500 font-mono">Identical feature records in sample</p>
                </div>
              </div>

              {/* Exploratory Feature Statistics Table */}
              {datasetEval?.sample_feature_statistics && (
                <div className="cyber-card space-y-4">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-2 border-b border-slate-800">
                    <div>
                      <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                        <Activity className="w-4 h-4 text-cyan-400" />
                        <span>SAMPLE FEATURE SUMMARY STATISTICS (EXPLORATORY PROFILING)</span>
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Distribution metrics across extracted numerical traffic features.
                      </p>
                    </div>
                    <div className="relative w-full sm:w-64">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        value={featureStatSearch}
                        onChange={(e) => setFeatureStatSearch(e.target.value)}
                        placeholder="Search feature name..."
                        className="cyber-input text-xs pl-8 py-1.5 w-full"
                      />
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40 max-h-96 overflow-y-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#1F2937]/90 text-slate-300 uppercase tracking-wider sticky top-0">
                        <tr>
                          <th className="px-4 py-3">Feature Name</th>
                          <th className="px-4 py-3 text-right">Mean</th>
                          <th className="px-4 py-3 text-right">Std Dev</th>
                          <th className="px-4 py-3 text-right">Min</th>
                          <th className="px-4 py-3 text-right">25%</th>
                          <th className="px-4 py-3 text-right">Median</th>
                          <th className="px-4 py-3 text-right">75%</th>
                          <th className="px-4 py-3 text-right">Max</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {filteredFeatureStats.length === 0 ? (
                          <tr>
                            <td colSpan={8} className="px-4 py-8 text-center text-slate-400">
                              No features match the filter.
                            </td>
                          </tr>
                        ) : (
                          filteredFeatureStats.map(([feat, stats]: [string, any]) => (
                            <tr key={feat} className="hover:bg-slate-800/30 transition">
                              <td className="px-4 py-3 text-cyan-300 font-semibold">{feat}</td>
                              <td className="px-4 py-3 text-slate-300 text-right">{stats.mean}</td>
                              <td className="px-4 py-3 text-slate-400 text-right">{stats.std}</td>
                              <td className="px-4 py-3 text-slate-300 text-right">{stats.min}</td>
                              <td className="px-4 py-3 text-slate-400 text-right">{stats.p25}</td>
                              <td className="px-4 py-3 text-slate-200 font-bold text-right">{stats.median}</td>
                              <td className="px-4 py-3 text-slate-400 text-right">{stats.p75}</td>
                              <td className="px-4 py-3 text-slate-300 text-right">{stats.max}</td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: COMPATIBILITY & SCHEMA MAPPING */}
          {activeTab === 'compatibility' && compatibility && (
            <div className="space-y-8 animate-fadeIn">
              {/* Overview Diagnosis Banner */}
              <div className="cyber-card p-6 border-l-4 border-l-cyan-500 space-y-4">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-3 border-b border-slate-800">
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-cyan-400" />
                      <span>FEATURE ADAPTATION & COMPATIBILITY ENGINE RESULTS</span>
                    </h3>
                    <p className="text-xs text-slate-400">
                      Multi-stage schema resolution: Canonical tokenization &rarr; Alias dictionary &rarr; Mathematical derivations
                    </p>
                  </div>
                  <span className={`px-3 py-1 rounded-lg text-xs font-mono font-bold border ${
                    compatibility.status === 'EXACT_MATCH'
                      ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                      : (compatibility.status === 'TRANSFORMABLE' || compatibility.status === 'TRANSFORMED_COMPATIBLE'
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/30')
                  }`}>
                    STATUS: {compatibility.status}
                  </span>
                </div>

                {/* Key Overview Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 font-mono text-xs">
                  <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                    <span className="text-slate-400 text-[11px]">Detected Dataset Format:</span>
                    <div className="font-bold text-slate-200 mt-1">{compatibility.detected_schema}</div>
                  </div>
                  <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                    <span className="text-slate-400 text-[11px]">Total Columns Inspected:</span>
                    <div className="font-bold text-cyan-300 mt-1">{compatibility.feature_columns_count} flow columns</div>
                  </div>
                  <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                    <span className="text-slate-400 text-[11px]">Execution Decision:</span>
                    <div className={`font-bold mt-1 ${!isEvaluationOnly ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {!isEvaluationOnly ? 'MODEL INFERENCE ACTIVE' : 'EVALUATION-ONLY'}
                    </div>
                  </div>
                  <div className="bg-slate-900/80 p-4 rounded-xl border border-slate-800">
                    <span className="text-slate-400 text-[11px]">Compatible Target Pipelines:</span>
                    <div className="font-bold text-slate-200 mt-1 truncate" title={compatibility.compatible_models?.join(', ')}>
                      {compatibility.compatible_models && compatibility.compatible_models.length > 0
                        ? compatibility.compatible_models.join(', ')
                        : 'None (Unsafe to Infer)'}
                    </div>
                  </div>
                </div>

                {/* Plain English Analysis & Recommendations */}
                <div className="p-4 bg-slate-950/70 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
                  <div className="text-slate-300 leading-relaxed">
                    <strong className="text-cyan-400">Diagnosis & Rationale: </strong>
                    {compatibility.explanation}
                  </div>
                  {compatibility.recommended_action && (
                    <div className="text-slate-400 leading-relaxed pt-1 border-t border-slate-800/80">
                      <strong className="text-emerald-400">Recommended Action: </strong>
                      {compatibility.recommended_action}
                    </div>
                  )}
                </div>
              </div>

              {/* Model Compatibility Matrix Cards */}
              {compatibility.models_evaluation && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                    <Database className="w-4 h-4 text-cyan-400" />
                    <span>MODEL TARGET COMPATIBILITY BREAKDOWN</span>
                  </h4>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* CICIDS2017 Card */}
                    {compatibility.models_evaluation.cicids2017 && (
                      <div className={`p-6 rounded-2xl border space-y-4 ${
                        compatibility.models_evaluation.cicids2017.is_inferable
                          ? 'bg-slate-900/90 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
                          : 'bg-slate-900/40 border-slate-800'
                      }`}>
                        <div className="flex justify-between items-start">
                          <div>
                            <span className="text-sm font-bold text-slate-200 font-mono">CICIDS2017 Classifier Pipeline</span>
                            <div className="text-xs text-slate-400 mt-0.5">70 Multiclass Flow Features Required</div>
                          </div>
                          <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg ${
                            compatibility.models_evaluation.cicids2017.is_inferable
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}>
                            {compatibility.models_evaluation.cicids2017.status} ({compatibility.models_evaluation.cicids2017.match_percentage}%)
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-3 text-center text-xs font-mono bg-slate-950/70 p-3 rounded-xl border border-slate-800">
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Exact Match</div>
                            <div className="text-emerald-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.cicids2017.matched_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Aliases</div>
                            <div className="text-cyan-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.cicids2017.transformed_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Derived</div>
                            <div className="text-indigo-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.cicids2017.derived_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Missing</div>
                            <div className="text-red-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.cicids2017.missing_count}</div>
                          </div>
                        </div>

                        {compatibility.models_evaluation.cicids2017.missing_count > 0 && (
                          <div className="text-xs text-slate-400 font-mono pt-1">
                            <span className="text-amber-400 font-semibold">Missing Essential: </span>
                            {compatibility.models_evaluation.cicids2017.missing_features.slice(0, 5).join(', ')}
                            {compatibility.models_evaluation.cicids2017.missing_features.length > 5 &&
                              ` (+${compatibility.models_evaluation.cicids2017.missing_features.length - 5} more)`}
                          </div>
                        )}
                      </div>
                    )}

                    {/* UNSW-NB15 Card */}
                    {compatibility.models_evaluation.unsw_nb15 && (
                      <div className={`p-6 rounded-2xl border space-y-4 ${
                        compatibility.models_evaluation.unsw_nb15.is_inferable
                          ? 'bg-slate-900/90 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
                          : 'bg-slate-900/40 border-slate-800'
                      }`}>
                        <div className="flex justify-between items-start">
                          <div>
                            <span className="text-sm font-bold text-slate-200 font-mono">UNSW-NB15 Classifier Pipeline</span>
                            <div className="text-xs text-slate-400 mt-0.5">42 Binary & Multiclass Connection Features</div>
                          </div>
                          <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-lg ${
                            compatibility.models_evaluation.unsw_nb15.is_inferable
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}>
                            {compatibility.models_evaluation.unsw_nb15.status} ({compatibility.models_evaluation.unsw_nb15.match_percentage}%)
                          </span>
                        </div>

                        <div className="grid grid-cols-4 gap-3 text-center text-xs font-mono bg-slate-950/70 p-3 rounded-xl border border-slate-800">
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Exact Match</div>
                            <div className="text-emerald-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.unsw_nb15.matched_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Aliases</div>
                            <div className="text-cyan-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.unsw_nb15.transformed_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Derived</div>
                            <div className="text-indigo-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.unsw_nb15.derived_count}</div>
                          </div>
                          <div>
                            <div className="text-[10px] text-slate-400 uppercase">Missing</div>
                            <div className="text-red-400 font-bold text-sm mt-0.5">{compatibility.models_evaluation.unsw_nb15.missing_count}</div>
                          </div>
                        </div>

                        {compatibility.models_evaluation.unsw_nb15.missing_count > 0 && (
                          <div className="text-xs text-slate-400 font-mono pt-1">
                            <span className="text-amber-400 font-semibold">Missing Essential: </span>
                            {compatibility.models_evaluation.unsw_nb15.missing_features.slice(0, 5).join(', ')}
                            {compatibility.models_evaluation.unsw_nb15.missing_features.length > 5 &&
                              ` (+${compatibility.models_evaluation.unsw_nb15.missing_features.length - 5} more)`}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Feature Mapping Report Table */}
              {compatibility.mapping_report && compatibility.mapping_report.length > 0 && (
                <div className="cyber-card space-y-4">
                  <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-2 border-b border-slate-800">
                    <div>
                      <h4 className="text-xs font-bold text-slate-100 font-mono flex items-center gap-2">
                        <Layers className="w-4 h-4 text-cyan-400" />
                        <span>TARGET FEATURE MAPPING & DERIVATION SPECIFICATION</span>
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Shows exact mapping rules, alias resolutions, and mathematical feature calculations.
                      </p>
                    </div>
                    <div className="relative w-full sm:w-64">
                      <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        value={mappingSearch}
                        onChange={(e) => setMappingSearch(e.target.value)}
                        placeholder="Search feature mapping..."
                        className="cyber-input text-xs pl-8 py-1.5 w-full"
                      />
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40 max-h-96 overflow-y-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#1F2937]/90 text-slate-300 uppercase tracking-wider sticky top-0">
                        <tr>
                          <th className="px-4 py-3">Target Model Feature</th>
                          <th className="px-4 py-3">Source Dataset Column</th>
                          <th className="px-4 py-3">Transformation Type</th>
                          <th className="px-4 py-3">Derivation Rule / Assumptions</th>
                          <th className="px-4 py-3 text-right">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {filteredMappings.length === 0 ? (
                          <tr>
                            <td colSpan={5} className="px-4 py-8 text-center text-slate-400">
                              No feature mappings match the search filter.
                            </td>
                          </tr>
                        ) : (
                          filteredMappings.map((m: any, idx: number) => (
                            <tr key={idx} className="hover:bg-slate-800/30 transition">
                              <td className="px-4 py-3 text-slate-200 font-semibold">{m.target_feature}</td>
                              <td className="px-4 py-3 text-cyan-300">{m.source_feature || '—'}</td>
                              <td className="px-4 py-3">
                                <span className={`px-2.5 py-1 rounded text-[10px] font-bold ${
                                  m.transform_type === 'EXACT_MATCH'
                                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                    : m.transform_type === 'ALIAS_MAPPED'
                                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                    : m.transform_type === 'DERIVED_CALCULATION'
                                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                                    : 'bg-red-500/20 text-red-300 border border-red-500/30'
                                }`}>
                                  {m.transform_type}
                                </span>
                              </td>
                              <td className="px-4 py-3 text-slate-400 text-xs max-w-sm truncate" title={m.assumptions}>
                                {m.assumptions}
                              </td>
                              <td className="px-4 py-3 text-right">
                                {m.status === 'mapped' ? (
                                  <span className="text-emerald-400 font-bold inline-flex items-center gap-1">
                                    <CheckCircle className="w-3.5 h-3.5" /> Mapped
                                  </span>
                                ) : (
                                  <span className="text-red-400 font-bold inline-flex items-center gap-1">
                                    <XCircle className="w-3.5 h-3.5" /> Missing
                                  </span>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
