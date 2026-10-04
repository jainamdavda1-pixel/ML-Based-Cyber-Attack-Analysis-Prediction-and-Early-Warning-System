import React, { useState } from 'react';
import { Crosshair, ChevronDown, ChevronRight, Cpu, ShieldAlert, CheckCircle, Zap } from 'lucide-react';
import { detectionApi } from '../services/detectionApi';
import { PredictionResult } from '../types/detection';
import { RiskBadge, AttackBadge } from '../components/common/Badge';

export const DetectionPage: React.FC<{ selectedDataset: string }> = ({ selectedDataset }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PredictionResult | null>(null);

  // Grouped feature inputs state
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    flow: true,
    forward: false,
    backward: false,
    packet: false,
    timing: false,
    tcp: false,
  });

  const cicidsDefaults: Record<string, number> = {
    'Destination Port': 80,
    'Flow Duration': 1500,
    'Total Fwd Packets': 10,
    'Total Backward Packets': 8,
    'Total Length of Fwd Packets': 500,
    'Total Length of Bwd Packets': 1200,
    'Fwd Packet Length Max': 150,
    'Fwd Packet Length Min': 40,
    'Bwd Packet Length Max': 300,
    'Bwd Packet Length Min': 40,
    'Flow Bytes/s': 1133.3,
    'Flow Packets/s': 12.0,
    'Flow IAT Mean': 150.0,
    'Flow IAT Std': 25.0,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 255,
    'min_seg_size_forward': 32,
  };

  const unswDefaults: Record<string, number> = {
    'dur': 0.001055,
    'proto': 6,
    'service': 0,
    'state': 2,
    'spkts': 2,
    'dpkts': 2,
    'sbytes': 132,
    'dbytes': 164,
    'rate': 2843.6,
    'sttl': 31,
    'dttl': 29,
    'sload': 500473.9,
    'dload': 621800.9,
    'sloss': 0,
    'dloss': 0,
    'sinpkt': 0.017,
    'dinpkt': 0.014,
    'sjit': 0.0,
    'djit': 0.0,
    'swin': 255,
    'stcpb': 0,
    'dtcpb': 0,
    'dwin': 255,
    'tcprtt': 0.0,
    'synack': 0.0,
    'ackdat': 0.0,
    'smean': 66,
    'dmean': 82,
    'trans_depth': 0,
    'response_body_len': 0,
    'ct_srv_src': 2,
    'ct_state_ttl': 0,
    'ct_dst_ltm': 1,
    'ct_src_dport_ltm': 1,
    'ct_dst_sport_ltm': 1,
    'ct_dst_src_ltm': 1,
    'is_ftp_login': 0,
    'ct_ftp_cmd': 0,
    'ct_flw_http_mthd': 0,
    'ct_src_ltm': 1,
    'ct_srv_dst': 2,
    'is_sm_ips_ports': 0
  };

  const generalizedDefaults: Record<string, number> = {
    'duration_seconds': 0.85,
    'forward_packets': 8,
    'backward_packets': 6,
    'forward_bytes': 650,
    'backward_bytes': 1800,
    'total_packets': 14,
    'total_bytes': 2450,
    'packets_per_second': 16.47,
    'bytes_per_second': 2882.35,
    'average_packet_size': 175.0
  };

  const getDefaultsForDataset = (ds: string) => {
    const clean = ds.toLowerCase();
    if (clean.includes('gen') || clean.includes('isolation') || clean.includes('iforest')) {
      return generalizedDefaults;
    }
    if (clean.includes('unsw')) {
      return unswDefaults;
    }
    return cicidsDefaults;
  };

  const [featureValues, setFeatureValues] = useState<Record<string, number>>(
    getDefaultsForDataset(selectedDataset)
  );

  React.useEffect(() => {
    setFeatureValues(getDefaultsForDataset(selectedDataset));
    setResult(null);
    setError(null);
  }, [selectedDataset]);

  const toggleSection = (section: string) => {
    setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const handleInputChange = (featureName: string, valStr: string) => {
    const val = parseFloat(valStr) || 0;
    setFeatureValues(prev => ({ ...prev, [featureName]: val }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await detectionApi.predictSingle(selectedDataset, featureValues);
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Prediction failed');
    } finally {
      setLoading(false);
    }
  };

  // Feature sections mapping
  const generalizedSections = [
    {
      id: 'flow',
      title: 'Core Flow & Volume Statistics',
      features: ['duration_seconds', 'total_packets', 'total_bytes', 'average_packet_size']
    },
    {
      id: 'forward',
      title: 'Directional Packet & Byte Breakdown',
      features: ['forward_packets', 'backward_packets', 'forward_bytes', 'backward_bytes']
    },
    {
      id: 'timing',
      title: 'Flow Transfer Rate Metrics',
      features: ['packets_per_second', 'bytes_per_second']
    }
  ];

  const cicidsSections = [
    {
      id: 'flow',
      title: 'Flow Information',
      features: ['Destination Port', 'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s']
    },
    {
      id: 'forward',
      title: 'Forward Traffic',
      features: ['Total Fwd Packets', 'Total Length of Fwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Fwd Header Length', 'Fwd Packets/s', 'act_data_pkt_fwd']
    },
    {
      id: 'backward',
      title: 'Backward Traffic',
      features: ['Total Backward Packets', 'Total Length of Bwd Packets', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Bwd Header Length', 'Bwd Packets/s']
    },
    {
      id: 'packet',
      title: 'Packet Statistics & Flags',
      features: ['Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count']
    },
    {
      id: 'timing',
      title: 'Timing & Inter-Arrival Time (IAT)',
      features: ['Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
    },
    {
      id: 'tcp',
      title: 'TCP & Window Information',
      features: ['Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'min_seg_size_forward', 'Down/Up Ratio', 'Fwd PSH Flags', 'Fwd URG Flags', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes']
    }
  ];

  const unswSections = [
    {
      id: 'flow',
      title: 'UNSW Core Flow Attributes',
      features: ['dur', 'proto', 'service', 'state', 'rate', 'sttl', 'dttl', 'is_sm_ips_ports']
    },
    {
      id: 'forward',
      title: 'Source & Destination Bytes/Packets',
      features: ['spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'sloss', 'dloss']
    },
    {
      id: 'timing',
      title: 'Timing & Jitter Attributes',
      features: ['sinpkt', 'dinpkt', 'sjit', 'djit', 'tcprtt', 'synack', 'ackdat']
    },
    {
      id: 'tcp',
      title: 'TCP Window & Connection Counts',
      features: ['swin', 'dwin', 'stcpb', 'dtcpb', 'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst']
    }
  ];

  const isGen = selectedDataset.toLowerCase().includes('gen') || selectedDataset.toLowerCase().includes('isolation') || selectedDataset.toLowerCase().includes('iforest');
  const activeSections = isGen ? generalizedSections : (selectedDataset.includes('unsw') ? unswSections : cicidsSections);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-100 font-mono flex items-center space-x-2">
          <Crosshair className="w-5 h-5 text-cyan-400" />
          <span>SINGLE NETWORK FLOW PREDICTION</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Evaluate individual network-flow feature vectors against trained models for attack classification and risk scoring.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Form Column */}
        <div className="lg:col-span-7 space-y-4">
          <div className="cyber-card">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-sm font-semibold text-slate-200 font-mono">
                Input Feature Values ({selectedDataset.toUpperCase()})
              </h3>
              <span className="text-xs text-cyan-400 font-mono">Collapsible Sections</span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-3">
              {activeSections.map(section => {
                const isOpen = openSections[section.id];
                return (
                  <div key={section.id} className="border border-slate-800 rounded-lg overflow-hidden bg-[#161F2E]/60">
                    <button
                      type="button"
                      onClick={() => toggleSection(section.id)}
                      className="w-full px-4 py-3 bg-[#1F2937]/80 hover:bg-[#1F2937] flex justify-between items-center text-xs font-mono font-medium text-slate-200 transition"
                    >
                      <span className="flex items-center space-x-2">
                        <span className="w-2 h-2 rounded-full bg-cyan-400" />
                        <span>{section.title}</span>
                        <span className="text-[10px] text-slate-500">({section.features.length} features)</span>
                      </span>
                      {isOpen ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                    </button>

                    {isOpen && (
                      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3 bg-slate-900/40 border-t border-slate-800">
                        {section.features.map(feat => (
                          <div key={feat} className="space-y-1">
                            <label className="text-[11px] font-mono text-slate-400 truncate block" title={feat}>
                              {feat}
                            </label>
                            <input
                              type="number"
                              step="any"
                              value={featureValues[feat] !== undefined ? featureValues[feat] : 0}
                              onChange={e => handleInputChange(feat, e.target.value)}
                              className="cyber-input w-full"
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}

              {error && (
                <div className="p-3 bg-red-950/60 border border-red-800 text-red-300 text-xs rounded-lg font-mono">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold font-mono text-xs rounded-lg transition flex items-center justify-center space-x-2 shadow-lg shadow-cyan-950/40"
              >
                {loading ? (
                  <>
                    <Zap className="w-4 h-4 animate-spin" />
                    <span>EXECUTING INFERENCE...</span>
                  </>
                ) : (
                  <>
                    <Crosshair className="w-4 h-4" />
                    <span>RUN ML PREDICTION & RISK ESTIMATION</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Results Display Column */}
        <div className="lg:col-span-5 space-y-4">
          <div className="cyber-card min-h-[400px]">
            <h3 className="text-sm font-semibold text-slate-200 font-mono mb-4 flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Inference Result Telemetry</span>
            </h3>

            {!result && !loading && (
              <div className="p-12 text-center text-slate-500 text-xs font-mono space-y-3">
                <Crosshair className="w-10 h-10 mx-auto text-slate-700 animate-pulse" />
                <p>Fill feature values and click "RUN ML PREDICTION" to evaluate the network flow.</p>
              </div>
            )}

            {result && (
              <div className="space-y-5">
                {/* Status Box */}
                <div className={`p-4 rounded-xl border ${result.is_attack ? 'bg-red-950/40 border-red-800/80' : 'bg-emerald-950/40 border-emerald-800/80'}`}>
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400">Classified Result</p>
                      <h4 className={`text-xl font-bold font-mono ${result.is_attack ? 'text-red-400' : 'text-emerald-400'}`}>
                        {result.prediction}
                      </h4>
                    </div>
                    <AttackBadge isAttack={result.is_attack} prediction={result.prediction} />
                  </div>
                </div>

                {/* Score Grid */}
                <div className="grid grid-cols-2 gap-3 font-mono">
                  <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">RISK SCORE</span>
                    <span className="text-xl font-bold text-amber-400">{result.risk_score} / 100</span>
                    <div className="mt-1">
                      <RiskBadge level={result.risk_level} size="sm" />
                    </div>
                  </div>

                  <div className="bg-slate-900/60 p-3.5 rounded-lg border border-slate-800">
                    <span className="text-[10px] text-slate-400 block">MODEL CONFIDENCE</span>
                    <span className="text-xl font-bold text-cyan-400">{(result.confidence * 100).toFixed(2)}%</span>
                    <span className="text-[10px] text-slate-500 block mt-1">Margin: {((result.prediction_margin || 0) * 100).toFixed(2)}%</span>
                  </div>
                </div>

                {/* Top Features */}
                {result.top_features && result.top_features.length > 0 && (
                  <div className="space-y-2">
                    <h5 className="text-xs font-semibold text-slate-300 font-mono">Strongly Contributing Features</h5>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {result.top_features.map(tf => (
                        <div key={tf.feature} className="flex justify-between items-center p-2 rounded bg-slate-900/40 text-[11px] font-mono border border-slate-800/60">
                          <span className="text-slate-300 truncate max-w-[180px]">{tf.feature}</span>
                          <div className="text-right">
                            <span className="text-cyan-400 font-semibold">{tf.value}</span>
                            <span className="text-[10px] text-slate-500 block">SHAP: {tf.importance}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
