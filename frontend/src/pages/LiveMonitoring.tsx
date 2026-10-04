import React, { useState, useEffect, useMemo } from 'react';
import { 
  Play, 
  Square, 
  Activity, 
  ShieldAlert, 
  Cpu, 
  Radio, 
  AlertTriangle, 
  Info, 
  ArrowRight, 
  Layers, 
  Eye, 
  Search, 
  Filter, 
  ChevronDown, 
  ChevronUp,
  ShieldCheck,
  CheckCircle2,
  Database
} from 'lucide-react';
import { monitoringApi } from '../services/monitoringApi';
import { MonitoringStatus, InterfaceInfo, LiveNetworkFlow } from '../types/monitoring';

interface LiveMonitoringProps {
  selectedDataset: string;
}

export function LiveMonitoringPage({ selectedDataset }: LiveMonitoringProps) {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('en0');
  const [status, setStatus] = useState<MonitoringStatus | null>(null);
  const [liveFlows, setLiveFlows] = useState<LiveNetworkFlow[]>([]);
  const [, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedFlow, setExpandedFlow] = useState<string | null>(null);

  // Filter & Search States
  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<'all' | 'attacks' | 'anomalies' | 'high_risk' | 'tcp' | 'udp'>('all');

  const getPipelineLabel = (ds: string) => {
    const clean = ds.toLowerCase();
    if (clean.includes('isolation') || clean.includes('iforest')) return 'ISOLATION FOREST';
    if (clean.includes('gen')) return 'GENERALIZED XGB';
    if (clean.includes('unsw')) return 'UNSW-NB15';
    return 'CICIDS2017';
  };

  const fetchStatusAndFlows = async () => {
    try {
      const [statRes, flowsRes] = await Promise.all([
        monitoringApi.getStatus(),
        monitoringApi.getLiveFlows(60)
      ]);
      setStatus(statRes);
      setLiveFlows(flowsRes.reverse());
      if (statRes.last_error) {
        setError(statRes.last_error);
      } else {
        setError(null);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to fetch live monitoring telemetry');
    }
  };

  useEffect(() => {
    const loadInterfaces = async () => {
      setLoading(true);
      try {
        const res = await monitoringApi.getInterfaces();
        const formatted: InterfaceInfo[] = (res.permitted_interfaces || []).map((item: any) => {
          if (typeof item === 'string') {
            return {
              name: item,
              description: item === 'test0' ? 'test0 - Virtual Simulation (Internal testing)' : `${item} - Network Interface`,
              is_virtual: item === 'test0',
              is_permitted: true
            };
          }
          return item;
        });

        setInterfaces(formatted);
        if (formatted.length > 0) {
          const defaultIface = formatted.find(i => i.name === 'en0') || formatted.find(i => i.name === 'lo0') || formatted[0];
          setSelectedInterface(defaultIface.name);
        }
      } catch (err: any) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };

    loadInterfaces();
    fetchStatusAndFlows();

    const interval = setInterval(() => {
      fetchStatusAndFlows();
    }, 1500);

    return () => clearInterval(interval);
  }, []);

  const handleStart = async () => {
    setActionLoading(true);
    setError(null);
    try {
      await monitoringApi.startMonitoring(selectedInterface, selectedDataset);
      await fetchStatusAndFlows();
    } catch (err: any) {
      setError(err.message || 'Failed to start live network monitoring');
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

  // Filtered flows computation
  const filteredFlows = useMemo(() => {
    return liveFlows.filter((flow) => {
      // 1. Text Search Filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesIp = (flow.src_ip && flow.src_ip.toLowerCase().includes(q)) || 
                          (flow.dst_ip && flow.dst_ip.toLowerCase().includes(q));
        const matchesPort = (flow.src_port?.toString().includes(q)) || 
                            (flow.dst_port?.toString().includes(q));
        const matchesProto = flow.protocol?.toLowerCase().includes(q);
        const matchesPred = flow.prediction?.toLowerCase().includes(q);
        if (!matchesIp && !matchesPort && !matchesProto && !matchesPred) return false;
      }

      // 2. Category Tab Filter
      if (activeFilter === 'attacks') return flow.is_attack;
      if (activeFilter === 'anomalies') return flow.is_anomaly;
      if (activeFilter === 'high_risk') return flow.risk_level === 'High' || flow.risk_level === 'Critical';
      if (activeFilter === 'tcp') return flow.protocol?.toUpperCase() === 'TCP';
      if (activeFilter === 'udp') return flow.protocol?.toUpperCase() === 'UDP';

      return true;
    });
  }, [liveFlows, searchQuery, activeFilter]);

  // Counts for tabs
  const attackCount = useMemo(() => liveFlows.filter(f => f.is_attack).length, [liveFlows]);
  const anomalyCount = useMemo(() => liveFlows.filter(f => f.is_anomaly).length, [liveFlows]);
  const highRiskCount = useMemo(() => liveFlows.filter(f => f.risk_level === 'High' || f.risk_level === 'Critical').length, [liveFlows]);

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 bg-slate-900/70 p-6 rounded-2xl border border-slate-800/80 backdrop-blur-xl shadow-lg shadow-black/20">
        <div>
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${isRunning ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400' : 'bg-slate-800/60 border-slate-700/60 text-slate-500'}`}>
              <Radio className={`h-5 w-5 ${isRunning ? 'animate-pulse' : ''}`} />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight">REAL NETWORK TRAFFIC MONITORING</h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Passive Scapy packet ingestion • Bidirectional flow aggregation • Dual ML inference (Generalized XGBoost + Isolation Forest)
              </p>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
          <div className="flex items-center gap-2 bg-slate-850 border border-slate-700/70 rounded-xl px-3 py-1.5 text-xs font-mono">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">ACTIVE MODEL:</span>
            <span className="font-bold text-cyan-300">{getPipelineLabel(selectedDataset)}</span>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning || actionLoading}
              className="bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 min-w-[140px]"
            >
              {interfaces.map((iface) => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} {iface.is_virtual ? '(Simulation)' : '(Hardware)'}
                </option>
              ))}
            </select>

            {isRunning ? (
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="flex items-center gap-2 bg-rose-600 hover:bg-rose-500 text-white font-mono font-bold text-xs px-4 py-2 rounded-xl transition-all shadow-lg shadow-rose-600/20 active:scale-95 disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
                <span>Stop Capture</span>
              </button>
            ) : (
              <button
                onClick={handleStart}
                disabled={actionLoading}
                className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs px-4 py-2 rounded-xl transition-all shadow-lg shadow-emerald-600/20 active:scale-95 disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Start Monitoring</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Permission / Runtime Error Banner */}
      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-xl text-rose-300 flex items-start gap-3 text-xs font-mono">
          <AlertTriangle className="h-5 w-5 text-rose-400 mt-0.5 flex-shrink-0" />
          <div className="space-y-1">
            <span className="font-bold text-rose-200 block">CAPTURE ERROR / PERMISSION NOTICE</span>
            <p>{error}</p>
            <p className="text-[11px] text-slate-400 pt-1">
              Tip: On macOS, live hardware capture requires BPF permissions (`sudo chmod 666 /dev/bpf*`) or running backend with sudo. You can also select the <strong className="text-cyan-300">test0 (Virtual Simulation)</strong> interface.
            </p>
          </div>
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 font-mono shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-medium">Capture State</span>
            <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${
              isRunning ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full ${isRunning ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
              {isRunning ? 'LIVE' : 'STANDBY'}
            </span>
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-2 tracking-tight">
            {isRunning ? `${status?.uptime_seconds ?? 0}s` : 'Offline'}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 truncate">
            Adapter: <span className="text-slate-300 font-semibold">{status?.interface || selectedInterface}</span>
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 font-mono shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-medium">Packets Captured</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-300 mt-2 tracking-tight">
            {status?.total_packets?.toLocaleString() || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Raw L3/L4 packet frames sniffed
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 font-mono shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-medium">Flows Processed</span>
            <Cpu className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-indigo-300 mt-2 tracking-tight flex items-baseline gap-2">
            <span>{status?.total_flows?.toLocaleString() || 0}</span>
            <span className="text-xs font-normal text-slate-400">({status?.flows_per_second ?? 0} flows/s)</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Canonical 10-feature aggregations
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-2xl p-4 font-mono shadow-sm">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-medium">Threats & Anomalies</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 mt-2 tracking-tight flex items-baseline gap-2">
            <span>{status?.total_attacks?.toLocaleString() || 0}</span>
            <span className="text-xs font-normal text-amber-400">/ {status?.total_anomalies ?? 0} anom</span>
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Supervised alerts + iForest outliers
          </div>
        </div>
      </div>

      {/* Live Stream Table Section */}
      <div className="bg-slate-900/70 border border-slate-800/90 rounded-2xl overflow-hidden backdrop-blur-xl shadow-xl shadow-black/30">
        
        {/* Table Top Bar: Filters & Search */}
        <div className="p-4 sm:p-5 border-b border-slate-800/80 space-y-3.5">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
                <Database className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-bold font-mono text-slate-100 tracking-wide">
                  LIVE NETWORK TRAFFIC FLOW FEED
                </h2>
                <p className="text-[11px] text-slate-400 font-mono">
                  Showing {filteredFlows.length} of {liveFlows.length} captured bidirectional flows (auto-refreshed every 1.5s)
                </p>
              </div>
            </div>

            {/* Search Input */}
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IP, Port, Proto..."
                className="w-full bg-slate-950/60 border border-slate-700/70 rounded-xl pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-2.5 top-2 text-[10px] font-mono text-slate-400 hover:text-slate-200"
                >
                  ✕
                </button>
              )}
            </div>
          </div>

          {/* Quick Filter Tabs */}
          <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/60 text-xs font-mono">
            <button
              onClick={() => setActiveFilter('all')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeFilter === 'all'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 border border-slate-700/50'
              }`}
            >
              All Flows ({liveFlows.length})
            </button>

            <button
              onClick={() => setActiveFilter('attacks')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeFilter === 'attacks'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold'
                  : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 border border-slate-700/50'
              }`}
            >
              Attacks ({attackCount})
            </button>

            <button
              onClick={() => setActiveFilter('anomalies')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeFilter === 'anomalies'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold'
                  : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 border border-slate-700/50'
              }`}
            >
              Anomalies ({anomalyCount})
            </button>

            <button
              onClick={() => setActiveFilter('high_risk')}
              className={`px-3 py-1 rounded-lg transition-all ${
                activeFilter === 'high_risk'
                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40 font-bold'
                  : 'bg-slate-800/50 text-slate-400 hover:text-slate-200 border border-slate-700/50'
              }`}
            >
              High/Critical Risk ({highRiskCount})
            </button>

            <div className="h-4 w-px bg-slate-800 mx-1 hidden sm:block" />

            <button
              onClick={() => setActiveFilter('tcp')}
              className={`px-2.5 py-1 rounded-lg transition-all ${
                activeFilter === 'tcp'
                  ? 'bg-cyan-900/40 text-cyan-300 border border-cyan-700/50 font-bold'
                  : 'bg-slate-800/40 text-slate-400 hover:text-slate-200 border border-slate-700/40'
              }`}
            >
              TCP
            </button>

            <button
              onClick={() => setActiveFilter('udp')}
              className={`px-2.5 py-1 rounded-lg transition-all ${
                activeFilter === 'udp'
                  ? 'bg-indigo-900/40 text-indigo-300 border border-indigo-700/50 font-bold'
                  : 'bg-slate-800/40 text-slate-400 hover:text-slate-200 border border-slate-700/40'
              }`}
            >
              UDP
            </button>
          </div>
        </div>

        {/* Table Data View */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead className="bg-[#131B2A] text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="px-4 py-3.5 w-24 font-semibold">Time</th>
                <th className="px-4 py-3.5 min-w-[190px] font-semibold">Source (IP : Port)</th>
                <th className="px-2 py-3.5 w-8 text-center text-slate-600"></th>
                <th className="px-4 py-3.5 min-w-[190px] font-semibold">Destination (IP : Port)</th>
                <th className="px-3 py-3.5 w-20 text-center font-semibold">Proto</th>
                <th className="px-4 py-3.5 min-w-[140px] font-semibold">Traffic Volume</th>
                <th className="px-4 py-3.5 min-w-[160px] font-semibold">XGBoost Verdict</th>
                <th className="px-4 py-3.5 min-w-[150px] font-semibold">iForest Score</th>
                <th className="px-4 py-3.5 min-w-[130px] font-semibold">Risk Level</th>
                <th className="px-4 py-3.5 w-20 text-center font-semibold">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={10} className="px-6 py-16 text-center text-slate-500 font-mono">
                    <div className="flex flex-col items-center justify-center space-y-3 max-w-md mx-auto">
                      <div className="p-3.5 rounded-2xl bg-slate-800/60 border border-slate-700/60 text-slate-400">
                        <Activity className="h-7 w-7" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-sm font-semibold text-slate-300">
                          {isRunning 
                            ? (searchQuery || activeFilter !== 'all' ? 'No flows match the active filters or search criteria.' : 'Waiting for packets to assemble into bidirectional flows...')
                            : 'No live traffic captured yet.'}
                        </p>
                        <p className="text-xs text-slate-500">
                          {isRunning 
                            ? 'Flows expire automatically after 3.0s of inactivity and are pushed directly to this table.'
                            : 'Select a network interface (e.g. en0 or test0) and click Start Monitoring above.'}
                        </p>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow) => {
                  const isExpanded = expandedFlow === flow.flow_id;
                  return (
                    <React.Fragment key={flow.flow_id}>
                      <tr className={`hover:bg-slate-800/50 transition-colors ${
                        flow.is_attack 
                          ? 'bg-rose-950/25 border-l-2 border-l-rose-500' 
                          : flow.is_anomaly 
                            ? 'bg-amber-950/20 border-l-2 border-l-amber-500' 
                            : 'border-l-2 border-l-transparent'
                      }`}>
                        {/* Timestamp */}
                        <td className="px-4 py-3 text-slate-400 text-[11px] whitespace-nowrap">
                          {flow.timestamp ? flow.timestamp.replace('T', ' ').substring(11, 19) : '--:--:--'}
                        </td>

                        {/* Source IP:Port */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-slate-100">{flow.src_ip}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700/60 font-mono">
                              :{flow.src_port}
                            </span>
                          </div>
                        </td>

                        {/* Direction Indicator */}
                        <td className="px-2 py-3 text-center text-slate-500">
                          <ArrowRight className="w-3.5 h-3.5 inline-block text-slate-600" />
                        </td>

                        {/* Destination IP:Port */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-slate-100">{flow.dst_ip}</span>
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700/60 font-mono">
                              :{flow.dst_port}
                            </span>
                          </div>
                        </td>

                        {/* Protocol */}
                        <td className="px-3 py-3 text-center whitespace-nowrap">
                          <span className={`inline-block px-2.5 py-0.5 rounded-md text-[10px] font-bold border ${
                            flow.protocol === 'TCP' ? 'bg-cyan-950/60 text-cyan-300 border-cyan-800/70' :
                            (flow.protocol === 'UDP' ? 'bg-indigo-950/60 text-indigo-300 border-indigo-800/70' : 'bg-slate-800 text-slate-300 border-slate-700')
                          }`}>
                            {flow.protocol}
                          </span>
                        </td>

                        {/* Traffic Volume */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="space-y-0.5">
                            <div className="text-slate-200 font-semibold">{flow.packet_count} pkts</div>
                            <div className="text-[11px] text-slate-500">
                              {flow.byte_count ? (flow.byte_count > 1024 ? `${(flow.byte_count / 1024).toFixed(1)} KB` : `${flow.byte_count} B`) : '0 B'}
                            </div>
                          </div>
                        </td>

                        {/* XGBoost Verdict */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="space-y-1">
                            <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[10px] font-bold border ${
                              flow.is_attack 
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' 
                                : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            }`}>
                              {flow.is_attack ? <AlertTriangle className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                              <span>{flow.prediction || (flow.is_attack ? 'ATTACK' : 'BENIGN')}</span>
                            </span>
                            <div className="text-[10px] text-slate-400">
                              Conf: <span className="font-semibold text-slate-300">{((flow.confidence || 0) * 100).toFixed(0)}%</span>
                            </div>
                          </div>
                        </td>

                        {/* Isolation Forest Score */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          {flow.anomaly_score !== undefined ? (
                            <div className="space-y-1">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold border ${
                                flow.is_anomaly 
                                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 animate-pulse' 
                                  : 'bg-slate-800/80 text-slate-300 border-slate-700'
                              }`}>
                                {flow.is_anomaly ? '⚠️ OUTLIER' : '✓ NORMAL'}
                              </span>
                              <div className="text-[10px] text-slate-400">
                                Score: <span className="font-mono text-slate-300">{flow.anomaly_score.toFixed(3)}</span>
                              </div>
                            </div>
                          ) : (
                            <span className="text-slate-500 text-[10px]">N/A</span>
                          )}
                        </td>

                        {/* Risk Assessment */}
                        <td className="px-4 py-3 whitespace-nowrap">
                          <div className="space-y-1">
                            <span className={`inline-block text-[10px] px-2.5 py-0.5 rounded-md font-bold border ${
                              flow.risk_level === 'Critical' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                              flow.risk_level === 'High' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                              flow.risk_level === 'Moderate' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                              'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                            }`}>
                              {flow.risk_level || 'Low'}
                            </span>
                            <div className="text-[10px] text-slate-400">
                              Score: <span className="font-semibold text-slate-300">{flow.risk_score ?? 0}/100</span>
                            </div>
                          </div>
                        </td>

                        {/* Inspect Action */}
                        <td className="px-4 py-3 text-center whitespace-nowrap">
                          <button
                            onClick={() => setExpandedFlow(isExpanded ? null : flow.flow_id)}
                            className={`p-1.5 rounded-lg border transition-all ${
                              isExpanded 
                                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50' 
                                : 'bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 border-slate-700'
                            }`}
                            title="Inspect 10 Canonical Flow Features"
                          >
                            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expanded Canonical Feature Inspection Card */}
                      {isExpanded && flow.features && (
                        <tr className="bg-slate-950/90 border-b border-slate-800">
                          <td colSpan={10} className="p-5">
                            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3.5 shadow-inner">
                              
                              {/* Inspection Header */}
                              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 pb-2.5 border-b border-slate-800 text-xs font-mono">
                                <div className="flex items-center gap-2 text-cyan-300 font-bold">
                                  <Activity className="w-4 h-4" />
                                  <span>10 CANONICAL CROSS-DATASET FEATURES (STANDARDIZED INPUT SCHEMA)</span>
                                </div>
                                <div className="text-[11px] text-slate-400">
                                  Flow Key: <span className="text-slate-200">{flow.flow_id}</span>
                                </div>
                              </div>

                              {/* 10 Features Grid */}
                              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 text-xs font-mono">
                                {[
                                  { label: 'duration_seconds', value: flow.features.duration_seconds, unit: 'sec' },
                                  { label: 'forward_packets', value: flow.features.forward_packets, unit: 'pkts' },
                                  { label: 'backward_packets', value: flow.features.backward_packets, unit: 'pkts' },
                                  { label: 'forward_bytes', value: flow.features.forward_bytes, unit: 'bytes' },
                                  { label: 'backward_bytes', value: flow.features.backward_bytes, unit: 'bytes' },
                                  { label: 'total_packets', value: flow.features.total_packets, unit: 'pkts' },
                                  { label: 'total_bytes', value: flow.features.total_bytes, unit: 'bytes' },
                                  { label: 'packets_per_second', value: flow.features.packets_per_second, unit: 'pps' },
                                  { label: 'bytes_per_second', value: flow.features.bytes_per_second, unit: 'B/s' },
                                  { label: 'average_packet_size', value: flow.features.average_packet_size, unit: 'bytes' },
                                ].map((feat) => (
                                  <div key={feat.label} className="p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
                                    <span className="text-[10px] text-slate-400 block truncate font-medium">
                                      {feat.label}
                                    </span>
                                    <div className="flex items-baseline justify-between">
                                      <span className="text-slate-100 font-bold text-xs">
                                        {typeof feat.value === 'number' 
                                          ? (feat.value % 1 !== 0 ? feat.value.toFixed(3) : feat.value.toLocaleString()) 
                                          : (feat.value ?? 0)}
                                      </span>
                                      <span className="text-[10px] text-cyan-400/80">{feat.unit}</span>
                                    </div>
                                  </div>
                                ))}
                              </div>

                              {/* Pipeline Diagnostics Summary */}
                              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 text-[11px] font-mono text-slate-400 border-t border-slate-800/80">
                                <div className="flex items-center gap-4">
                                  <span>XGBoost Prob: <strong className="text-slate-200">{((flow.confidence || 0) * 100).toFixed(1)}%</strong> (Threshold: 0.50)</span>
                                  <span>iForest Score: <strong className="text-slate-200">{flow.anomaly_score !== undefined ? flow.anomaly_score.toFixed(4) : 'N/A'}</strong> (Threshold: 0.0234)</span>
                                </div>
                                <div className="text-emerald-400 flex items-center gap-1">
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  <span>Passed canonical preprocessing validation</span>
                                </div>
                              </div>

                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer */}
        <div className="p-3.5 bg-slate-950/60 border-t border-slate-800/80 flex flex-col sm:flex-row justify-between items-center text-[11px] font-mono text-slate-400 gap-2">
          <div className="flex items-center gap-2">
            <span>Buffer limit: 60 flows</span>
            <span>•</span>
            <span>Inactivity timeout: 3.0s</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-slate-500">Protocols: TCP, UDP, ICMP</span>
            <span className="text-cyan-400">Zero payload stored</span>
          </div>
        </div>

      </div>
    </div>
  );
}

