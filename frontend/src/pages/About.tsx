import React from 'react';
import { BookOpen, ShieldCheck, Cpu, Database, AlertTriangle, GitBranch } from 'lucide-react';

export const AboutPage: React.FC<{ selectedDataset?: string }> = ({ selectedDataset = 'cicids2017' }) => {
  const isUnsw = selectedDataset.toLowerCase().includes('unsw');

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-3">
            <BookOpen className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-bold text-slate-100 font-mono">PROJECT METHODOLOGY & SYSTEM ARCHITECTURE</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Academic documentation, dataset separation policy, machine learning model pipeline, and risk calibration specifications.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-xl border border-slate-700 text-xs font-mono text-cyan-400">
          <Database className="w-3.5 h-3.5" />
          <span>Active Pipeline: {selectedDataset.toUpperCase()}</span>
        </div>
      </div>

      {/* Project Objective Card */}
      <div className="cyber-card space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Project Overview & Research Objectives</span>
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          "ML-Based Cyber Attack Analysis, Prediction and Early Warning System" is a production-style research platform built to ingest, classify, and analyze network flow traffic in real time. It combines multiclass XGBoost models with SHAP explainability and calibrated decision thresholds to deliver actionable early warnings for security operations.
        </p>
      </div>

      {/* Dataset Separation Policy */}
      <div className="cyber-card space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
          <Database className="w-4 h-4 text-cyan-400" />
          <span>Strict Dataset Separation Policy</span>
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          The system maintains strict dataset separation between two independent benchmarks. Label taxonomies and feature spaces are NOT merged:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono pt-2">
          <div className={`p-4 rounded-xl border transition-all ${
            selectedDataset.toLowerCase().includes('cicids')
              ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md shadow-cyan-500/10'
              : 'bg-slate-900/60 border-slate-800'
          }`}>
            <span className="font-bold text-cyan-400 block text-sm">1. CICIDS2017 Benchmark {selectedDataset.toLowerCase().includes('cicids') && '(Active)'}</span>
            <p className="text-slate-300 text-xs mt-1">70 Network Flow Features • 15 Attack Classes • 383,203 Test Evaluation Samples • XGBoost Multiclass Architecture</p>
            <p className="text-[11px] text-slate-400 mt-2">Decision Threshold: 0.94 • Microsecond flow duration scaling</p>
          </div>

          <div className={`p-4 rounded-xl border transition-all ${
            selectedDataset.toLowerCase().includes('unsw')
              ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md shadow-cyan-500/10'
              : 'bg-slate-900/60 border-slate-800'
          }`}>
            <span className="font-bold text-cyan-400 block text-sm">2. UNSW-NB15 Benchmark {selectedDataset.toLowerCase().includes('unsw') && '(Active)'}</span>
            <p className="text-slate-300 text-xs mt-1">42 Network Flow Features • 10 Attack Classes • 82,332 Test Evaluation Samples • Random Forest & XGBoost Binary/Multiclass</p>
            <p className="text-[11px] text-slate-400 mt-2">Decision Boundary: 0.50 • Connection state & load features</p>
          </div>

          <div className={`p-4 rounded-xl border transition-all ${
            selectedDataset.toLowerCase().includes('gen')
              ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md shadow-cyan-500/10'
              : 'bg-slate-900/60 border-slate-800'
          }`}>
            <span className="font-bold text-cyan-400 block text-sm">3. Generalized Cross-Dataset XGBoost {selectedDataset.toLowerCase().includes('gen') && '(Active)'}</span>
            <p className="text-slate-300 text-xs mt-1">10 Canonical Flow Aggregations • Binary Attack Detector • Calibrated Decision Threshold 0.1743</p>
            <p className="text-[11px] text-slate-400 mt-2">Cross-dataset robustness targeting 1% Benign False Positive Rate</p>
          </div>

          <div className={`p-4 rounded-xl border transition-all ${
            selectedDataset.toLowerCase().includes('isolation') || selectedDataset.toLowerCase().includes('iforest')
              ? 'bg-cyan-950/40 border-cyan-500/50 shadow-md shadow-cyan-500/10'
              : 'bg-slate-900/60 border-slate-800'
          }`}>
            <span className="font-bold text-cyan-400 block text-sm">4. Baseline Isolation Forest { (selectedDataset.toLowerCase().includes('isolation') || selectedDataset.toLowerCase().includes('iforest')) && '(Active)'}</span>
            <p className="text-slate-300 text-xs mt-1">10 Canonical Flow Aggregations • Unsupervised Zero-Day Outlier Isolation</p>
            <p className="text-[11px] text-slate-400 mt-2">Decision Threshold: 0.023416 on clean baseline traffic (contamination 10%)</p>
          </div>
        </div>
      </div>

      {/* Risk Calibration & Thresholding */}
      <div className="cyber-card space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          <span>Calibrated Risk Scoring Formula</span>
        </h3>
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2 text-xs font-mono">
          <div className="text-cyan-400 font-bold">P(Attack) = 1.0 - P(Normal / BENIGN)</div>
          <div className="text-amber-400 font-bold">Risk Score = P(Attack) × 100.0</div>
          <p className="text-slate-400 text-[11px] pt-1">
            Decision thresholds are calibrated per model: CICIDS2017 at frozen threshold <span className="text-slate-200 font-semibold">0.94</span> (99.48% precision, 99.96% recall); UNSW-NB15 at validation boundary <span className="text-slate-200 font-semibold">0.50</span> (98.20% precision, 98.70% recall); Generalized XGBoost at <span className="text-slate-200 font-semibold">0.1743</span> (1% benign FPR); Isolation Forest at <span className="text-slate-200 font-semibold">0.023416</span> outlier decision score.
          </p>
        </div>
      </div>

      {/* Architecture Pipeline */}
      <div className="cyber-card space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <span>System End-to-End Execution Pipeline</span>
        </h3>
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-1 bg-slate-800 rounded">1. Dataset Selection ({selectedDataset.toUpperCase()})</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">2. Network Flow CSV / PCAP / Live Capture</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">3. ML Inference</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">4. Attack Classification</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">5. Risk Estimation</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">6. Early Warning & SHAP Explanation</span>
          </div>
        </div>
      </div>
    </div>
  );
};
