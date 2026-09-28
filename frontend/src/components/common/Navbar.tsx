import React from 'react';
import { Activity, Database, Server } from 'lucide-react';

interface NavbarProps {
  selectedDataset: string;
  onDatasetChange: (ds: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ selectedDataset, onDatasetChange }) => {
  return (
    <header className="h-16 bg-[#111827]/80 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-4">
        <span className="flex items-center space-x-2 text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2.5 py-1 rounded-full border border-emerald-800/50">
          <Activity className="w-3.5 h-3.5 animate-pulse" />
          <span>SYSTEM ACTIVE</span>
        </span>
        <span className="text-slate-500 text-xs font-mono">|</span>
        <span className="text-xs text-slate-400 font-mono">FastAPI Backend Operational</span>
      </div>

      <div className="flex items-center space-x-3">
        <label className="text-xs text-slate-400 font-medium flex items-center space-x-1.5">
          <Database className="w-3.5 h-3.5 text-cyan-400" />
          <span>Active Dataset / Model:</span>
        </label>
        <select
          value={selectedDataset}
          onChange={(e) => onDatasetChange(e.target.value)}
          className="bg-[#1F2937] border border-slate-700 text-cyan-400 text-xs font-mono font-semibold rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="cicids2017">CICIDS2017 (Multiclass XGBoost)</option>
          <option value="unsw-nb15">UNSW-NB15 (Binary & Multiclass)</option>
        </select>
      </div>
    </header>
  );
};
