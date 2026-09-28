import React, { useState } from 'react';
import { Sidebar } from './components/common/Sidebar';
import { Navbar } from './components/common/Navbar';
import { DashboardPage } from './pages/Dashboard';
import { LiveMonitoringPage } from './pages/LiveMonitoring';
import { IncidentsPage } from './pages/Incidents';
import { DetectionPage } from './pages/Detection';
import { BatchAnalysisPage } from './pages/BatchAnalysis';
import { RiskPage } from './pages/Risk';
import { AttackAnalysisPage } from './pages/AttackAnalysis';
import { ModelPerformancePage } from './pages/ModelPerformance';
import { AlertsPage } from './pages/Alerts';
import { AboutPage } from './pages/About';

export function App() {
  const [currentTab, setCurrentTab] = useState('dashboard');
  const [selectedDataset, setSelectedDataset] = useState('cicids2017');

  return (
    <div className="flex min-h-screen bg-[#0B0F19] text-slate-100">
      {/* Sidebar */}
      <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <Navbar selectedDataset={selectedDataset} onDatasetChange={setSelectedDataset} />

        <main className="flex-1 p-6 overflow-y-auto">
          {currentTab === 'dashboard' && <DashboardPage selectedDataset={selectedDataset} />}
          {currentTab === 'monitoring' && <LiveMonitoringPage selectedDataset={selectedDataset} />}
          {currentTab === 'incidents' && <IncidentsPage selectedDataset={selectedDataset} />}
          {currentTab === 'detection' && <DetectionPage selectedDataset={selectedDataset} />}
          {currentTab === 'batch' && <BatchAnalysisPage selectedDataset={selectedDataset} />}
          {currentTab === 'risk' && <RiskPage selectedDataset={selectedDataset} />}
          {currentTab === 'explainability' && <AttackAnalysisPage selectedDataset={selectedDataset} />}
          {currentTab === 'performance' && (
            <ModelPerformancePage
              selectedDataset={selectedDataset}
              onDatasetChange={setSelectedDataset}
            />
          )}
          {currentTab === 'history' && <AlertsPage selectedDataset={selectedDataset} />}
          {currentTab === 'about' && <AboutPage selectedDataset={selectedDataset} />}
        </main>
      </div>
    </div>
  );
}

export default App;

