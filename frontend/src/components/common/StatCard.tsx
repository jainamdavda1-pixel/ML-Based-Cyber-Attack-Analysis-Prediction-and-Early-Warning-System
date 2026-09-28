import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: string;
  color?: 'cyan' | 'emerald' | 'amber' | 'red' | 'indigo';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'cyan'
}) => {
  const iconColor = {
    cyan: 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60',
    emerald: 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60',
    amber: 'text-amber-400 bg-amber-950/60 border-amber-800/60',
    red: 'text-red-400 bg-red-950/60 border-red-800/60',
    indigo: 'text-indigo-400 bg-indigo-950/60 border-indigo-800/60'
  }[color];

  return (
    <div className="cyber-card flex items-start justify-between">
      <div>
        <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">{title}</p>
        <h3 className="text-2xl font-bold font-mono text-slate-100 mt-1">{value}</h3>
        {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
        {trend && (
          <span className="inline-block text-xs font-mono text-cyan-400 mt-2">
            {trend}
          </span>
        )}
      </div>
      <div className={`p-2.5 rounded-xl border ${iconColor}`}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
};
