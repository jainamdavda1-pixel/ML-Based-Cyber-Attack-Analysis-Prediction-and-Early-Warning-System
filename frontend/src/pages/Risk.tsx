import React, { useEffect, useState } from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle2, Info, Sliders } from 'lucide-react';
import { riskApi } from '../services/riskApi';
import { EarlyWarningMetrics, RiskCalculation } from '../types/risk';
import { RiskBadge } from '../components/common/Badge';
import { ConfusionMatrixGrid } from '../components/charts/ConfusionMatrixGrid';

export const RiskPage: React.FC = () => {
  const [benignProbInput, setBenignProbInput] = useState<number>(0.10);
  const [calculatedRisk, setCalculatedRisk] = useState<RiskCalculation | null>(null);
  const [metrics, setMetrics] = useState<EarlyWarningMetrics | null>(null);

  useEffect(() => {
    loadRisk(benignProbInput);
    riskApi.getEarlyWarningMetrics().then(setMetrics).catch(console.error);
  }, []);

  const loadRisk = async (pBenign: number) => {
    try {
      const res = await riskApi.calculateRisk(pBenign);
      setCalculatedRisk(res);
    } catch (e) {
      console.error(e);
    }
  };

  const handleSliderChange = (val: number) => {
    setBenignProbInput(val);
    loadRisk(val);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <span>RISK SCORING & EARLY WARNING TELEMETRY</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Calibrated threat risk scoring methodology based on decision probability distributions and early warning thresholding.
        </p>
      </div>

      {/* Calibrated Risk Note Banner */}
      <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/80 flex items-start space-x-3">
        <Info className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <p className="font-semibold text-cyan-300 font-mono">CALIBRATED RISK SCORE METHODOLOGY</p>
          <p>
            "Risk score is based on <span className="font-mono text-cyan-400">P(Attack) = 1 - P(BENIGN)</span> and is calibrated using the project's validation threshold."
          </p>
          <p className="text-[11px] text-slate-400">
            Note: Risk scores are categorized into project-defined risk bands (0–30 Low, 30–60 Moderate, 60–80 High, 80–100 Critical) and represent relative likelihood metrics rather than universal standards.
          </p>
        </div>
      </div>

      {/* Interactive Risk Simulator */}
      <div className="cyber-card">
        <h3 className="text-sm font-semibold text-slate-200 font-mono mb-4 flex items-center space-x-2">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <span>Interactive Risk Score Simulator</span>
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          <div className="lg:col-span-6 space-y-4">
            <div>
              <div className="flex justify-between text-xs font-mono text-slate-300 mb-1">
                <span>BENIGN Probability P(BENIGN):</span>
                <span className="font-bold text-cyan-400">{(benignProbInput * 100).toFixed(1)}%</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.01"
                value={benignProbInput}
                onChange={(e) => handleSliderChange(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 bg-slate-800 h-2 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-1">
                <span>0.0 (High Threat)</span>
                <span>0.5</span>
                <span>1.0 (Safe Benign)</span>
              </div>
            </div>
          </div>

          <div className="lg:col-span-6 bg-slate-900/60 p-4 rounded-xl border border-slate-800 flex justify-around items-center font-mono">
            <div>
              <span className="text-[10px] text-slate-400 block">P(Attack)</span>
              <span className="text-xl font-bold text-red-400">
                {calculatedRisk ? (calculatedRisk.attack_probability * 100).toFixed(2) : 0}%
              </span>
            </div>

            <div className="h-8 w-px bg-slate-800" />

            <div>
              <span className="text-[10px] text-slate-400 block">RISK SCORE</span>
              <span className="text-2xl font-bold text-amber-400">
                {calculatedRisk ? calculatedRisk.risk_score : 0} / 100
              </span>
            </div>

            <div className="h-8 w-px bg-slate-800" />

            <div>
              <span className="text-[10px] text-slate-400 block">RISK BAND</span>
              {calculatedRisk && <RiskBadge level={calculatedRisk.risk_level} size="lg" />}
            </div>
          </div>
        </div>
      </div>

      {/* Project Risk Bands Definition */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card border-l-4 border-l-emerald-500">
          <span className="text-xs font-mono text-emerald-400 font-bold block">LOW RISK (0 – 30)</span>
          <p className="text-xs text-slate-400 mt-1">Standard benign operational traffic. High P(BENIGN) confidence.</p>
        </div>

        <div className="cyber-card border-l-4 border-l-amber-500">
          <span className="text-xs font-mono text-amber-400 font-bold block">MODERATE RISK (30 – 60)</span>
          <p className="text-xs text-slate-400 mt-1">Borderline flow characteristics or rare benign background variance.</p>
        </div>

        <div className="cyber-card border-l-4 border-l-orange-500">
          <span className="text-xs font-mono text-orange-400 font-bold block">HIGH RISK (60 – 80)</span>
          <p className="text-xs text-slate-400 mt-1">Strong attack probability. Exceeds early-warning alert thresholds.</p>
        </div>

        <div className="cyber-card border-l-4 border-l-red-600">
          <span className="text-xs font-mono text-red-400 font-bold block">CRITICAL RISK (80 – 100)</span>
          <p className="text-xs text-slate-400 mt-1">Near-certain cyber attack detection. Immediate automated mitigation recommended.</p>
        </div>
      </div>

      {/* Frozen Threshold Evaluation Telemetry */}
      {metrics && (
        <div className="cyber-card space-y-4">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-200 font-mono">
                Frozen Validation Threshold (0.94) Performance Telemetry
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluation results on 383,203 held-out CICIDS2017 test samples at threshold = 0.94
              </p>
            </div>
            <span className="text-xs font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 px-3 py-1 rounded-full">
              Threshold: 0.94
            </span>
          </div>

          {/* Test Metrics Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono text-center">
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">PRECISION</span>
              <span className="text-sm font-bold text-emerald-400">{metrics.test_metrics_frozen.precision.toFixed(2)}%</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">RECALL</span>
              <span className="text-sm font-bold text-emerald-400">{metrics.test_metrics_frozen.recall.toFixed(2)}%</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">F1-SCORE</span>
              <span className="text-sm font-bold text-cyan-400">{metrics.test_metrics_frozen.f1_score.toFixed(2)}%</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">ACCURACY</span>
              <span className="text-sm font-bold text-cyan-400">{metrics.test_metrics_frozen.accuracy.toFixed(2)}%</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">FALSE POSITIVE RATE</span>
              <span className="text-sm font-bold text-amber-400">{metrics.test_metrics_frozen.false_positive_rate.toFixed(4)}%</span>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-400 block">FALSE NEGATIVE RATE</span>
              <span className="text-sm font-bold text-emerald-400">{metrics.test_metrics_frozen.false_negative_rate.toFixed(4)}%</span>
            </div>
          </div>

          {/* Confusion Matrix Grid */}
          <div className="pt-2">
            <h4 className="text-xs font-semibold text-slate-300 font-mono mb-3">Confusion Matrix (383,203 Test Samples)</h4>
            <ConfusionMatrixGrid
              tn={metrics.test_metrics_frozen.confusion_matrix.true_negatives}
              fp={metrics.test_metrics_frozen.confusion_matrix.false_positives}
              fn={metrics.test_metrics_frozen.confusion_matrix.false_negatives}
              tp={metrics.test_metrics_frozen.confusion_matrix.true_positives}
            />
          </div>
        </div>
      )}
    </div>
  );
};
