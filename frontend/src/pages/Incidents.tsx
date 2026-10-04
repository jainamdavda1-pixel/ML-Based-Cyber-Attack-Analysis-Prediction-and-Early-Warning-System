import React, { useState, useEffect } from 'react';
import { ShieldAlert, Filter, Search, Edit3, CheckCircle, Clock, AlertTriangle, ChevronRight, FileText, Database } from 'lucide-react';
import { incidentsApi } from '../services/incidentsApi';
import { Incident } from '../types/incident';

interface IncidentsPageProps {
  selectedDataset?: string;
}

export function IncidentsPage({ selectedDataset = 'cicids2017' }: IncidentsPageProps) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [explanation, setExplanation] = useState<any | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('All');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  const [loading, setLoading] = useState(false);
  const [editingNotes, setEditingNotes] = useState(false);
  const [notesText, setNotesText] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('New');

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const s = statusFilter === 'All' ? undefined : statusFilter;
      const sev = severityFilter === 'All' ? undefined : severityFilter;
      const data = await incidentsApi.listIncidents(s, sev);
      setIncidents(data);
    } catch (err) {
      console.error('Failed to load incidents', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter, severityFilter]);

  const handleSelectIncident = async (inc: Incident) => {
    setSelectedIncident(inc);
    setSelectedStatus(inc.status);
    setNotesText(inc.notes || '');
    setEditingNotes(false);
    try {
      const exp = await incidentsApi.getExplanations(inc.incident_id);
      setExplanation(exp);
    } catch (err) {
      setExplanation(null);
    }
  };

  const handleSaveIncident = async () => {
    if (!selectedIncident) return;
    try {
      const updated = await incidentsApi.updateIncident(selectedIncident.incident_id, {
        status: selectedStatus,
        notes: notesText,
        analyst: 'Security Analyst'
      });
      setSelectedIncident(updated);
      setEditingNotes(false);
      fetchIncidents();
    } catch (err) {
      console.error('Failed to update incident', err);
    }
  };

  const getPipelineLabel = (ds: string) => {
    const clean = ds.toLowerCase();
    if (clean.includes('isolation') || clean.includes('iforest')) return 'ISOLATION FOREST';
    if (clean.includes('gen')) return 'GENERALIZED XGB';
    if (clean.includes('unsw')) return 'UNSW-NB15';
    return 'CICIDS2017';
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div>
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-6 w-6 text-rose-400" />
            <h1 className="text-2xl font-bold text-slate-100">Security Incident Management & Correlation</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Correlated multi-flow attack incidents, analyst triage lifecycle, and SHAP attribution evidence.
          </p>
        </div>

        {/* Filters & Pipeline Indicator */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-800/80 px-3 py-1.5 rounded-xl border border-slate-700 text-xs font-mono text-cyan-400">
            <Database className="w-3.5 h-3.5" />
            <span>Active Pipeline: {getPipelineLabel(selectedDataset)}</span>
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="All">All Statuses</option>
            <option value="New">New</option>
            <option value="Investigating">Investigating</option>
            <option value="Acknowledged">Acknowledged</option>
            <option value="Resolved">Resolved</option>
            <option value="False Positive">False Positive</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incident List */}
        <div className="lg:col-span-1 bg-slate-900/60 border border-slate-800 rounded-2xl p-4 backdrop-blur-xl h-[calc(100vh-280px)] overflow-y-auto space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <span className="text-xs font-semibold uppercase text-slate-400">Incident Queue</span>
            <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded-full">{incidents.length}</span>
          </div>

          {incidents.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-sm">
              No correlated incidents matching filters.
            </div>
          ) : (
            incidents.map((inc) => (
              <div
                key={inc.incident_id}
                onClick={() => handleSelectIncident(inc)}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  selectedIncident?.incident_id === inc.incident_id
                    ? 'bg-slate-800 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-800/40 border-slate-800 hover:bg-slate-800/70 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                    inc.severity === 'Critical' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                    inc.severity === 'High' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                    'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}>
                    {inc.severity}
                  </span>
                  <span className="text-xs text-slate-400 bg-slate-900 px-2 py-0.5 rounded">
                    {inc.status}
                  </span>
                </div>

                <div className="font-medium text-slate-100 text-sm mt-2 line-clamp-1">{inc.title}</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">
                  {inc.src_ip} → {inc.dst_ip}
                </div>

                <div className="flex items-center justify-between text-xs text-slate-500 mt-3 pt-2 border-t border-slate-800/50">
                  <span>{inc.flow_count} Correlated Flows</span>
                  <span className="font-semibold text-rose-400">Risk: {inc.risk_score.toFixed(1)}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Incident Detail & Investigation Pane */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl space-y-6">
          {selectedIncident ? (
            <>
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-cyan-400">{selectedIncident.incident_id}</span>
                    <span className="text-slate-500">•</span>
                    <span className="text-xs text-slate-400">Category: {selectedIncident.attack_category}</span>
                  </div>
                  <h2 className="text-xl font-bold text-slate-100 mt-1">{selectedIncident.title}</h2>
                </div>

                <div className="flex items-center gap-2">
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    className="bg-slate-800 border border-slate-700 text-slate-200 text-xs rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="New">New</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Acknowledged">Acknowledged</option>
                    <option value="Resolved">Resolved</option>
                    <option value="False Positive">False Positive</option>
                  </select>

                  <button
                    onClick={handleSaveIncident}
                    className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium px-4 py-2 rounded-xl transition-all shadow-md shadow-cyan-600/20"
                  >
                    Save Changes
                  </button>
                </div>
              </div>

              {/* Metadata Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-slate-800/40 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400">Source Host</span>
                  <div className="font-mono text-sm font-semibold text-slate-200 mt-1">{selectedIncident.src_ip}</div>
                </div>
                <div className="bg-slate-800/40 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400">Target Host</span>
                  <div className="font-mono text-sm font-semibold text-slate-200 mt-1">{selectedIncident.dst_ip}</div>
                </div>
                <div className="bg-slate-800/40 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400">Flow Count</span>
                  <div className="text-sm font-semibold text-slate-200 mt-1">{selectedIncident.flow_count}</div>
                </div>
                <div className="bg-slate-800/40 p-4 rounded-xl border border-slate-800">
                  <span className="text-xs text-slate-400">Peak Risk Score</span>
                  <div className="text-sm font-semibold text-rose-400 mt-1">{selectedIncident.risk_score.toFixed(1)} / 100</div>
                </div>
              </div>

              {/* Analyst Notes */}
              <div className="bg-slate-800/40 p-5 rounded-xl border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold uppercase text-slate-300 flex items-center gap-2">
                    <FileText className="h-4 w-4 text-cyan-400" /> Analyst Investigation Notes
                  </span>
                </div>
                <textarea
                  value={notesText}
                  onChange={(e) => setNotesText(e.target.value)}
                  rows={4}
                  placeholder="Document threat indicators, firewall action, or verification findings..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-sans"
                />
              </div>

              {/* SHAP Explanation Attribution */}
              {explanation?.explanation?.top_global_features && (
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-slate-200">Key Feature Attributions (SHAP Attribution)</h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {explanation.explanation.top_global_features.slice(0, 6).map((feat: any) => (
                      <div key={feat.feature} className="bg-slate-800/40 p-3 rounded-xl border border-slate-800/60">
                        <div className="flex justify-between items-center text-xs">
                          <span className="font-medium text-slate-200">{feat.feature}</span>
                          <span className="font-mono text-cyan-400">+{feat.mean_shap_value}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">{feat.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-24 text-slate-500 space-y-3">
              <ShieldAlert className="h-10 w-10 text-slate-600" />
              <p className="text-sm">Select an incident from the queue to review metadata, triage, and record analyst notes.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
