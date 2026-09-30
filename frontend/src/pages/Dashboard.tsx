import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity, RefreshCw, Layers } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { RiskBadge, AttackBadge } from '../components/common/Badge';
import { RiskDistributionChart } from '../components/charts/RiskDistributionChart';
import { AttackCategoryChart } from '../components/charts/AttackCategoryChart';
import { alertsApi } from '../services/alertsApi';
import { DashboardSummary } from '../types/alert';

export const DashboardPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const isUnsw = selectedDataset.toLowerCase().includes('unsw');

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await alertsApi.getDashboardSummary(selectedDataset);
      setSummary(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedDataset]);

  // Compute risk level distribution directly from summary
  const riskDist = summary?.risk_distribution || {
    Low: summary?.low_risk_count || 0,
    Moderate: summary?.moderate_risk_count || 0,
    High: summary?.high_risk_count || 0,
    Critical: summary?.critical_risk_count || 0
  };

  // Compute category distribution directly from summary or fallback
  const categoryDist: Record<string, number> = {};
  if (summary?.category_distribution && Object.keys(summary.category_distribution).length > 0) {
    Object.assign(categoryDist, summary.category_distribution);
  } else if (summary?.recent_alerts && summary.recent_alerts.length > 0) {
    summary.recent_alerts.forEach(a => {
      categoryDist[a.prediction] = (categoryDist[a.prediction] || 0) + 1;
    });
  }

  // Dataset-specific chart defaults when no live data has been recorded yet
  const defaultCategories: Record<string, number> = isUnsw
    ? { Normal: 20, Generic: 8, Exploits: 5, Fuzzers: 4, DoS: 3, Reconnaissance: 2 }
    : { BENIGN: 25, PortScan: 6, DDoS: 4, 'DoS Hulk': 3, 'FTP-Patator': 2 };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/70 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 rounded-xl border border-cyan-500/20">
              <Activity className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-wide">
                SECURITY MONITORING DASHBOARD
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time threat detection, multi-class attack classification, and early warning risk telemetry.
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono px-3 py-1.5 rounded-xl bg-slate-800 text-cyan-400 border border-slate-700 flex items-center gap-2 font-bold">
            <Layers className="w-3.5 h-3.5" />
            <span>PIPELINE: {isUnsw ? 'UNSW-NB15' : 'CICIDS2017'}</span>
          </span>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-2 px-3.5 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Flow Records"
          value={summary?.total_analyzed ?? 0}
          subtitle={`Telemetry: ${isUnsw ? 'UNSW-NB15' : 'CICIDS2017'}`}
          icon={ShieldCheck}
          color="indigo"
        />
        <StatCard
          title="Attacks Detected"
          value={summary?.attacks_detected ?? 0}
          subtitle={`Attack Ratio: ${summary?.attack_percentage ?? 0}%`}
          icon={ShieldAlert}
          color="red"
        />
        <StatCard
          title="Average Risk Score"
          value={`${summary?.average_risk_score ?? 0}/100`}
          subtitle="P(Attack) calibrated index"
          icon={Activity}
          color="amber"
        />
        <StatCard
          title="Critical Threats"
          value={summary?.critical_risk_count ?? 0}
          subtitle={`High Risk: ${summary?.high_risk_count ?? 0}`}
          icon={AlertTriangle}
          color="cyan"
        />
      </div>

      {/* Visual Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="cyber-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>Attack Category Distribution ({isUnsw ? 'UNSW-NB15' : 'CICIDS2017'})</span>
            </h3>
            {Object.keys(categoryDist).length === 0 && (
              <span className="text-[10px] font-mono text-slate-500 italic">Baseline Reference</span>
            )}
          </div>
          <AttackCategoryChart
            distribution={Object.keys(categoryDist).length > 0 ? categoryDist : defaultCategories}
          />
        </div>

        <div className="cyber-card">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
              <span className="w-2 h-2 rounded-full bg-amber-400" />
              <span>Risk Level Telemetry ({isUnsw ? 'UNSW-NB15' : 'CICIDS2017'})</span>
            </h3>
            {!summary || summary.total_analyzed === 0 && (
              <span className="text-[10px] font-mono text-slate-500 italic">Baseline Reference</span>
            )}
          </div>
          <RiskDistributionChart
            distribution={summary && summary.total_analyzed > 0 ? riskDist : { Low: 20, Moderate: 5, High: 3, Critical: 2 }}
          />
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="cyber-card space-y-4">
        <div className="flex justify-between items-center">
          <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>Recent Security Event Logs ({isUnsw ? 'UNSW-NB15' : 'CICIDS2017'})</span>
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            Showing top {summary?.recent_alerts?.length ?? 0} events
          </span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">Loading security events...</div>
        ) : !summary || summary.recent_alerts.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono border border-dashed border-slate-800 rounded-xl">
            No events logged for {isUnsw ? 'UNSW-NB15' : 'CICIDS2017'} yet. Run a single flow detection or batch CSV analysis to generate alerts.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/40">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#1F2937]/90 text-slate-300 uppercase tracking-wider sticky top-0">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Dataset</th>
                  <th className="px-4 py-3">Prediction</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Risk Level</th>
                  <th className="px-4 py-3">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {summary.recent_alerts.map((alert) => (
                  <tr key={alert.prediction_id} className="hover:bg-slate-800/30 transition">
                    <td className="px-4 py-3 text-slate-400">{alert.timestamp.replace('T', ' ').substring(0, 19)}</td>
                    <td className="px-4 py-3 text-cyan-400 font-bold">{alert.dataset}</td>
                    <td className="px-4 py-3 font-semibold text-slate-100">{alert.prediction}</td>
                    <td className="px-4 py-3">
                      <AttackBadge isAttack={alert.is_attack} prediction={alert.prediction} />
                    </td>
                    <td className="px-4 py-3 font-bold text-slate-200">{alert.risk_score}</td>
                    <td className="px-4 py-3">
                      <RiskBadge level={alert.risk_level} size="sm" />
                    </td>
                    <td className="px-4 py-3 text-slate-300">{(alert.confidence * 100).toFixed(2)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
