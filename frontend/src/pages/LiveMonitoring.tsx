import React, { useState, useEffect } from 'react';
import { Play, Square, Activity, ShieldAlert, Cpu, Radio, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { monitoringApi } from '../services/monitoringApi';
import { MonitoringStatus } from '../types/monitoring';
import { NetworkFlow } from '../types/traffic';

interface LiveMonitoringProps {
  selectedDataset: string;
}

export function LiveMonitoringPage({ selectedDataset }: LiveMonitoringProps) {
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('test0');
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [liveFlows, setLiveFlows] = useState<NetworkFlow[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatusAndFlows = async () => {
    try {
      const [statRes, flowsRes] = await Promise.all([
        monitoringApi.getStatus(),
        monitoringApi.getLiveFlows(30)
      ]);
      setStatus(statRes);
      setLiveFlows(flowsRes.reverse());
      setError(null);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch live monitoring status');
    }
  };

  useEffect(() => {
    const loadInterfaces = async () => {
      setLoading(true);
      try {
        const res = await monitoringApi.getInterfaces();
        setInterfaces(res.permitted_interfaces || ['test0']);
        if (res.permitted_interfaces?.length > 0) {
          setSelectedInterface(res.permitted_interfaces[0]);
        }
      } catch (err: any) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    loadInterfaces();
    fetchStatusAndFlows();

    // Poll live status every 2 seconds
    const interval = setInterval(() => {
      fetchStatusAndFlows();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setActionLoading(true);
    setError(null);
    try {
      await monitoringApi.startMonitoring(selectedInterface, selectedDataset);
      await fetchStatusAndFlows();
    } catch (err: any) {
      setError(err.message || 'Failed to start live monitoring');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    setError(null);
    try {
      await monitoringApi.stopMonitoring();
      await fetchStatusAndFlows();
    } catch (err: any) {
      setError(err.message || 'Failed to stop live monitoring');
    } finally {
      setActionLoading(false);
    }
  };

  const isRunning = status?.running ?? false;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-3">
            <Radio className={`h-6 w-6 ${isRunning ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <h1 className="text-2xl font-bold text-slate-100">Authorized Live Network Monitoring</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Real-time passive packet inspection, ML flow aggregation, and telemetry classification on permitted interfaces.
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select
            value={selectedInterface}
            onChange={(e) => setSelectedInterface(e.target.value)}
            disabled={isRunning || actionLoading}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50"
          >
            {interfaces.map((iface) => (
              <option key={iface} value={iface}>
                Interface: {iface}
              </option>
            ))}
          </select>

          {isRunning ? (
            <button
              onClick={handleStop}
              disabled={actionLoading}
              className="flex items-center gap-2 bg-rose-600 hover:bg-rose-500 text-white font-medium px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-rose-600/20 disabled:opacity-50"
            >
              <Square className="h-4 w-4" />
              Stop Capture
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-5 py-2.5 rounded-xl transition-all shadow-lg shadow-emerald-600/20 disabled:opacity-50"
            >
              <Play className="h-4 w-4" />
              Start Monitoring
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 mt-0.5 flex-shrink-0" />
          <div className="text-sm font-medium">{error}</div>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-400 font-medium">Status</span>
            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${
              isRunning ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-800 text-slate-400'
            }`}>
              {isRunning ? '● LIVE' : 'STOPPED'}
            </span>
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2">
            {isRunning ? `${status?.uptime_seconds}s Uptime` : 'Offline'}
          </div>
          <p className="text-xs text-slate-500 mt-1">Interface: {status?.interface || selectedInterface}</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-400 font-medium">Packets Captured</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2">
            {status?.total_packets?.toLocaleString() || 0}
          </div>
          <p className="text-xs text-slate-500 mt-1">Ingested via bounded ring buffer</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-400 font-medium">Classified Flows</span>
            <Cpu className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2">
            {status?.total_flows?.toLocaleString() || 0}
          </div>
          <p className="text-xs text-slate-500 mt-1">Model: {selectedDataset.toUpperCase()}</p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-sm text-slate-400 font-medium">Threats Detected</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2">
            {status?.total_attacks?.toLocaleString() || 0}
          </div>
          <p className="text-xs text-slate-500 mt-1">Auto-correlated to incidents</p>
        </div>
      </div>

      {/* Live Stream Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur-xl">
        <div className="p-5 border-b border-slate-800 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-200">Live Traffic Flow Feed</h2>
            <span className="text-xs bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full">
              {liveFlows.length} recent flows
            </span>
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping"></span>
            Real-time feed
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-800/60 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-5 py-3.5">Source IP : Port</th>
                <th className="px-5 py-3.5">Destination IP : Port</th>
                <th className="px-5 py-3.5">Protocol</th>
                <th className="px-5 py-3.5">Packets</th>
                <th className="px-5 py-3.5">Prediction</th>
                <th className="px-5 py-3.5">Confidence</th>
                <th className="px-5 py-3.5">Risk Score</th>
                <th className="px-5 py-3.5">Risk Level</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {liveFlows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-5 py-12 text-center text-slate-500">
                    {isRunning
                      ? 'Waiting for packets to assemble into flows...'
                      : 'Monitoring is offline. Select an interface and click Start Monitoring.'}
                  </td>
                </tr>
              ) : (
                liveFlows.map((flow) => (
                  <tr key={flow.flow_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-300">
                      {flow.src_ip}:{flow.src_port}
                    </td>
                    <td className="px-5 py-3.5 font-mono text-xs text-slate-300">
                      {flow.dst_ip}:{flow.dst_port}
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs font-mono bg-slate-800 px-2 py-0.5 rounded text-slate-400">
                        {flow.protocol}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs text-slate-400">{flow.packet_count}</td>
                    <td className="px-5 py-3.5">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                        flow.is_attack ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      }`}>
                        {flow.prediction}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs font-mono">{(flow.confidence * 100).toFixed(1)}%</td>
                    <td className="px-5 py-3.5 font-mono text-xs font-semibold">
                      <span className={flow.risk_score >= 80 ? 'text-rose-400' : (flow.risk_score >= 50 ? 'text-amber-400' : 'text-emerald-400')}>
                        {flow.risk_score.toFixed(1)}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                        flow.risk_level === 'Critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                        flow.risk_level === 'High' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                        flow.risk_level === 'Moderate' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                        'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {flow.risk_level}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
