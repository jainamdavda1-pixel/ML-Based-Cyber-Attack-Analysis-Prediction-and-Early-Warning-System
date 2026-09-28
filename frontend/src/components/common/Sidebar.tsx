import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Crosshair, 
  UploadCloud, 
  AlertTriangle, 
  Cpu, 
  BarChart3, 
  History, 
  BookOpen 
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'detection', label: 'Single Prediction', icon: Crosshair },
    { id: 'batch', label: 'Batch Analysis', icon: UploadCloud },
    { id: 'risk', label: 'Risk & Early Warning', icon: AlertTriangle },
    { id: 'explainability', label: 'SHAP Explainability', icon: Cpu },
    { id: 'performance', label: 'Model Performance', icon: BarChart3 },
    { id: 'history', label: 'Prediction History', icon: History },
    { id: 'about', label: 'About & Methodology', icon: BookOpen },
  ];

  return (
    <aside className="w-64 bg-[#111827] border-r border-slate-800 flex flex-col min-h-screen">
      <div className="p-5 border-b border-slate-800 flex items-center space-x-3">
        <div className="p-2 bg-cyan-950/80 border border-cyan-700/80 rounded-lg text-cyan-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-slate-100 tracking-wide">CYBER-ATTACK ML</h1>
          <p className="text-[10px] text-cyan-400 font-mono">Prediction & Early Warning</p>
        </div>
      </div>

      <nav className="flex-1 p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-cyan-950/70 text-cyan-400 border border-cyan-800/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-800 text-[11px] text-slate-500 font-mono">
        <p>CICIDS2017 & UNSW-NB15</p>
        <p className="text-[10px] text-slate-600 mt-0.5">Dual Dataset Architecture</p>
      </div>
    </aside>
  );
};
