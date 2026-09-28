import React, { useEffect, useState } from 'react';
import { History, Search, Filter, ShieldAlert, Eye, X, ShieldCheck } from 'lucide-react';
import { alertsApi } from '../services/alertsApi';
import { AlertItem } from '../types/alert';
import { RiskBadge, AttackBadge } from '../components/common/Badge';

export const AlertsPage: React.FC = () => {
  const [history, setHistory] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await alertsApi.getHistory(100, undefined, riskFilter || undefined);
      setHistory(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [riskFilter]);

  const filteredHistory = history.filter(item => {
    const matchesSearch = item.prediction.toLowerCase().includes(search.toLowerCase()) ||
                          item.prediction_id.toLowerCase().includes(search.toLowerCase()) ||
                          item.dataset.toLowerCase().includes(search.toLowerCase());
    return matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <History className="w-5 h-5 text-cyan-400" />
          <span>PREDICTION HISTORY & SECURITY ALERTS</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Historical log database containing evaluated flow predictions, threat classifications, and mitigation recommendations.
        </p>
      </div>

      {/* Filter Bar */}
      <div className="cyber-card flex flex-col sm:flex-row gap-4 justify-between items-center">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search prediction ID or category..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="cyber-input w-full pl-9"
          />
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-cyan-400" />
          <select
            value={riskFilter}
            onChange={e => setRiskFilter(e.target.value)}
            className="cyber-input text-xs"
          >
            <option value="">All Risk Levels</option>
            <option value="Critical">Critical Risk</option>
            <option value="High">High Risk</option>
            <option value="Moderate">Moderate Risk</option>
            <option value="Low">Low Risk</option>
          </select>
        </div>
      </div>

      {/* History Table */}
      <div className="cyber-card">
        {loading ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">Loading prediction history...</div>
        ) : filteredHistory.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">No historical records match the filter criteria.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#1F2937]/70 text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Dataset</th>
                  <th className="px-4 py-3">Prediction</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Risk Score</th>
                  <th className="px-4 py-3">Risk Level</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filteredHistory.map(alert => (
                  <tr key={alert.prediction_id} className="hover:bg-slate-800/40">
                    <td className="px-4 py-3 text-slate-400">{alert.timestamp.replace('T', ' ').substring(0, 19)}</td>
                    <td className="px-4 py-3 text-cyan-400">{alert.prediction_id}</td>
                    <td className="px-4 py-3 text-slate-300">{alert.dataset}</td>
                    <td className="px-4 py-3 font-semibold text-slate-100">{alert.prediction}</td>
                    <td className="px-4 py-3">
                      <AttackBadge isAttack={alert.is_attack} prediction={alert.prediction} />
                    </td>
                    <td className="px-4 py-3 font-bold text-slate-200">{alert.risk_score}</td>
                    <td className="px-4 py-3">
                      <RiskBadge level={alert.risk_level} size="sm" />
                    </td>
                    <td className="px-4 py-3 text-slate-400 capitalize">{alert.input_source}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setSelectedAlert(alert)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-md border border-slate-700 transition"
                        title="View Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal View */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="cyber-card max-w-xl w-full space-y-4 relative border-cyan-800/80">
            <button
              onClick={() => setSelectedAlert(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-100"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3 border-b border-slate-800 pb-3">
              <ShieldAlert className="w-6 h-6 text-cyan-400" />
              <div>
                <h3 className="text-base font-bold text-slate-100 font-mono">Prediction Details</h3>
                <p className="text-xs text-slate-400 font-mono">{selectedAlert.prediction_id}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="bg-slate-900/60 p-3 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">PREDICTED CLASS</span>
                <span className="font-bold text-slate-100 text-sm">{selectedAlert.prediction}</span>
              </div>
              <div className="bg-slate-900/60 p-3 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">RISK LEVEL</span>
                <div className="mt-1"><RiskBadge level={selectedAlert.risk_level} size="sm" /></div>
              </div>
              <div className="bg-slate-900/60 p-3 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">RISK SCORE</span>
                <span className="font-bold text-amber-400 text-sm">{selectedAlert.risk_score} / 100</span>
              </div>
              <div className="bg-slate-900/60 p-3 rounded border border-slate-800">
                <span className="text-slate-400 block text-[10px]">CONFIDENCE</span>
                <span className="font-bold text-cyan-400 text-sm">{(selectedAlert.confidence * 100).toFixed(2)}%</span>
              </div>
            </div>

            {selectedAlert.recommendations && selectedAlert.recommendations.length > 0 && (
              <div className="space-y-2 pt-2">
                <h4 className="text-xs font-semibold text-slate-300 font-mono">Automated Security Recommendations</h4>
                <ul className="text-xs text-slate-300 space-y-1.5 font-mono list-disc list-inside bg-slate-900/60 p-3 rounded border border-slate-800">
                  {selectedAlert.recommendations.map((rec, idx) => (
                    <li key={idx} className="text-slate-300">{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
