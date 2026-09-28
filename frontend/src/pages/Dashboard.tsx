import React, { useEffect, useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Activity, RefreshCw } from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { RiskBadge, AttackBadge } from '../components/common/Badge';
import { RiskDistributionChart } from '../components/charts/RiskDistributionChart';
import { AttackCategoryChart } from '../components/charts/AttackCategoryChart';
import { alertsApi } from '../services/alertsApi';
import { DashboardSummary } from '../types/alert';

export const DashboardPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await alertsApi.getDashboardSummary();
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

  const riskDist = {
    Low: 0,
    Moderate: 0,
    High: summary?.high_risk_count || 0,
    Critical: summary?.critical_risk_count || 0
  };

  const categoryDist: Record<string, number> = {};
  if (summary?.recent_alerts) {
    summary.recent_alerts.forEach(a => {
      categoryDist[a.prediction] = (categoryDist[a.prediction] || 0) + 1;
    });
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>SECURITY MONITORING DASHBOARD</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time cyber attack detection, threat classification, and early warning risk telemetry.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center space-x-2 px-3 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Flow Records"
          value={summary?.total_analyzed ?? 0}
          subtitle="Processed network flows"
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
          <h3 className="text-sm font-semibold text-slate-200 mb-4 font-mono flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Attack Category Distribution</span>
          </h3>
          <AttackCategoryChart distribution={Object.keys(categoryDist).length > 0 ? categoryDist : { BENIGN: 12, PortScan: 4, DDoS: 2 }} />
        </div>

        <div className="cyber-card">
          <h3 className="text-sm font-semibold text-slate-200 mb-4 font-mono flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>Risk Level Telemetry</span>
          </h3>
          <RiskDistributionChart distribution={summary ? riskDist : { Low: 80, Moderate: 15, High: 4, Critical: 1 }} />
        </div>
      </div>

      {/* Recent Alerts Table */}
      <div className="cyber-card">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-sm font-semibold text-slate-200 font-mono flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>Recent Security Event Logs</span>
          </h3>
          <span className="text-xs text-slate-400 font-mono">
            Showing top {summary?.recent_alerts?.length ?? 0} events
          </span>
        </div>

        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">Loading security events...</div>
        ) : !summary || summary.recent_alerts.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            No threat history logged yet. Run a single flow prediction or batch CSV analysis to generate alerts.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#1F2937]/70 text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Dataset</th>
                  <th className="px-4 py-3">Prediction</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Risk Level</th>
                  <th className="px-4 py-3">Confidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {summary.recent_alerts.map((alert) => (
                  <tr key={alert.prediction_id} className="hover:bg-slate-800/40 transition">
                    <td className="px-4 py-3 text-slate-400">{alert.timestamp.replace('T', ' ').substring(0, 19)}</td>
                    <td className="px-4 py-3 text-cyan-400">{alert.dataset}</td>
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
