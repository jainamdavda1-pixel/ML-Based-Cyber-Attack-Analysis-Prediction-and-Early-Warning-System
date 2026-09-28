import React from 'react';

interface ConfusionMatrixGridProps {
  tn: number;
  fp: number;
  fn: number;
  tp: number;
}

export const ConfusionMatrixGrid: React.FC<ConfusionMatrixGridProps> = ({ tn, fp, fn, tp }) => {
  const total = tn + fp + fn + tp;
  const tnPct = ((tn / total) * 100).toFixed(2);
  const fpPct = ((fp / total) * 100).toFixed(2);
  const fnPct = ((fn / total) * 100).toFixed(2);
  const tpPct = ((tp / total) * 100).toFixed(2);

  return (
    <div className="w-full font-mono text-xs">
      <div className="grid grid-cols-2 gap-3">
        {/* TN */}
        <div className="bg-emerald-950/40 border border-emerald-800/50 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex justify-between items-center">
            <span className="text-emerald-400 font-semibold uppercase">True Negative (TN)</span>
            <span className="text-[10px] bg-emerald-900/60 text-emerald-300 px-2 py-0.5 rounded-full">{tnPct}%</span>
          </div>
          <div className="text-2xl font-bold text-emerald-300 mt-2">{tn.toLocaleString()}</div>
          <span className="text-[10px] text-slate-400 mt-1">BENIGN correctly classified as BENIGN</span>
        </div>

        {/* FP */}
        <div className="bg-amber-950/40 border border-amber-800/50 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex justify-between items-center">
            <span className="text-amber-400 font-semibold uppercase">False Positive (FP)</span>
            <span className="text-[10px] bg-amber-900/60 text-amber-300 px-2 py-0.5 rounded-full">{fpPct}%</span>
          </div>
          <div className="text-2xl font-bold text-amber-300 mt-2">{fp.toLocaleString()}</div>
          <span className="text-[10px] text-slate-400 mt-1">BENIGN falsely flagged as ATTACK</span>
        </div>

        {/* FN */}
        <div className="bg-red-950/40 border border-red-800/50 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex justify-between items-center">
            <span className="text-red-400 font-semibold uppercase">False Negative (FN)</span>
            <span className="text-[10px] bg-red-900/60 text-red-300 px-2 py-0.5 rounded-full">{fnPct}%</span>
          </div>
          <div className="text-2xl font-bold text-red-300 mt-2">{fn.toLocaleString()}</div>
          <span className="text-[10px] text-slate-400 mt-1">ATTACK missed as BENIGN</span>
        </div>

        {/* TP */}
        <div className="bg-cyan-950/40 border border-cyan-800/50 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex justify-between items-center">
            <span className="text-cyan-400 font-semibold uppercase">True Positive (TP)</span>
            <span className="text-[10px] bg-cyan-900/60 text-cyan-300 px-2 py-0.5 rounded-full">{tpPct}%</span>
          </div>
          <div className="text-2xl font-bold text-cyan-300 mt-2">{tp.toLocaleString()}</div>
          <span className="text-[10px] text-slate-400 mt-1">ATTACK correctly detected</span>
        </div>
      </div>
    </div>
  );
};
