import React from 'react';
import { BookOpen, ShieldCheck, Cpu, Database, AlertTriangle, GitBranch } from 'lucide-react';

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <span>PROJECT METHODOLOGY & SYSTEM ARCHITECTURE</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Academic documentation, dataset separation policy, machine learning model pipeline, and risk calibration specifications.
        </p>
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
          <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
            <span className="font-bold text-cyan-400 block">1. CICIDS2017 Dataset</span>
            <p className="text-slate-400 text-[11px]">70 Network Flow Features • 15 Attack Classes • 383,203 Test Evaluation Samples • XGBoost Multiclass Architecture</p>
          </div>
          <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-lg space-y-1">
            <span className="font-bold text-cyan-400 block">2. UNSW-NB15 Dataset</span>
            <p className="text-slate-400 text-[11px]">42 Network Flow Features • 10 Attack Classes • 82,332 Test Evaluation Samples • Random Forest & XGBoost Binary/Multiclass</p>
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
          <div className="text-cyan-400 font-bold">P(Attack) = 1.0 - P(BENIGN)</div>
          <div className="text-amber-400 font-bold">Risk Score = P(Attack) × 100.0</div>
          <p className="text-slate-400 text-[11px] pt-1">
            Frozen Validation Threshold: <span className="text-slate-200 font-semibold">0.94</span> selected on validation dataset. Held-out test performance at frozen threshold 0.94 achieved <span className="text-emerald-400">99.48% Precision</span>, <span className="text-emerald-400">99.96% Recall</span>, and <span className="text-amber-400">0.1052% False Positive Rate</span>.
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
          <div className="flex items-center space-x-2">
            <span className="px-2 py-1 bg-slate-800 rounded">1. Dataset Selection</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">2. Network Flow CSV / Manual Input</span>
            <span>→</span>
            <span className="px-2 py-1 bg-slate-800 rounded">3. ML Inference</span>
          </div>
          <div className="flex items-center space-x-2 pt-2">
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
