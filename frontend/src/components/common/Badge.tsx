import React from 'react';

interface RiskBadgeProps {
  level: 'Low' | 'Moderate' | 'High' | 'Critical' | string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md' }) => {
  let colorStyle = 'bg-slate-800 text-slate-300 border-slate-700';
  
  if (level === 'Low') {
    colorStyle = 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80';
  } else if (level === 'Moderate') {
    colorStyle = 'bg-amber-950/80 text-amber-400 border-amber-800/80';
  } else if (level === 'High') {
    colorStyle = 'bg-orange-950/80 text-orange-400 border-orange-800/80';
  } else if (level === 'Critical') {
    colorStyle = 'bg-red-950/90 text-red-400 border-red-800/90 animate-pulse';
  }

  const sizeStyle = size === 'sm' ? 'px-2 py-0.5 text-xs' : size === 'lg' ? 'px-3.5 py-1 text-sm font-semibold' : 'px-2.5 py-1 text-xs font-medium';

  return (
    <span className={`inline-flex items-center font-mono rounded-full border ${colorStyle} ${sizeStyle}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {level}
    </span>
  );
};

interface AttackBadgeProps {
  isAttack: boolean;
  prediction: string;
}

export const AttackBadge: React.FC<AttackBadgeProps> = ({ isAttack, prediction }) => {
  if (!isAttack) {
    return (
      <span className="inline-flex items-center px-2.5 py-1 text-xs font-medium font-mono rounded-md bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
        BENIGN
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2.5 py-1 text-xs font-medium font-mono rounded-md bg-red-950/60 text-red-400 border border-red-800/50">
      ATTACK: {prediction}
    </span>
  );
};
