import React, { useState, useEffect } from 'react';
import { ThemeProvider } from '@mui/material/styles';
import { CssBaseline, Box, LinearProgress, Typography } from '@mui/material';
import { muiCyberTheme } from './theme/muiTheme.js';
import { AuthProvider } from './context/AuthContext.js';
import { Sidebar } from './components/Sidebar.js';
import { Header } from './components/Header.js';
import { NavTab } from './components/Navigation.js';
import { DashboardPage } from './components/pages/DashboardPage.js';
import { EvaluationPage } from './components/pages/EvaluationPage.js';
import { DatasetPage } from './components/pages/DatasetPage.js';
import { ModelPage } from './components/pages/ModelPage.js';
import { InferencePage } from './components/pages/InferencePage.js';
import { DistributionShiftPage } from './components/pages/DistributionShiftPage.js';
import { HistoryPage } from './components/pages/HistoryPage.js';
import { ConfigPage } from './components/pages/ConfigPage.js';
import { MethodologyPage } from './components/pages/MethodologyPage.js';
import { FindingDrawer } from './components/FindingDrawer.js';
import { Finding, PlatformStats } from './types.js';
import {
  fetchPlatformStats,
  fetchHealth,
  seedDemoData,
  clearDemoData,
  explainFindingsWithGemini,
} from './api/client.js';

function AppContent() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [isLoadingStats, setIsLoadingStats] = useState(true);
  const [mlStatus, setMlStatus] = useState<'ONLINE' | 'OFFLINE' | 'CHECKING'>('CHECKING');
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Finding drawer state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [geminiExplanation, setGeminiExplanation] = useState<string | null>(null);
  const [isExplaining, setIsExplaining] = useState(false);

  const loadPlatformData = async () => {
    setIsLoadingStats(true);
    try {
      const [statsData, healthData] = await Promise.all([
        fetchPlatformStats().catch(() => null),
        fetchHealth().catch(() => null),
      ]);

      if (statsData) setStats(statsData);

      if (healthData && healthData.mlEngine) {
        setMlStatus(healthData.mlEngine.status === 'ONLINE' ? 'ONLINE' : 'OFFLINE');
      } else {
        setMlStatus('OFFLINE');
      }
    } catch (err) {
      console.warn('Initial telemetry load warning:', err);
    } finally {
      setIsLoadingStats(false);
    }
  };

  useEffect(() => {
    loadPlatformData();
  }, []);

  const handleSeedDemo = async () => {
    setIsActionLoading(true);
    try {
      await seedDemoData();
      await loadPlatformData();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleClearDemo = async () => {
    setIsActionLoading(true);
    try {
      await clearDemoData();
      await loadPlatformData();
    } catch (err) {
      alert((err as Error).message);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleFindingClick = (finding: Finding) => {
    setSelectedFinding(finding);
    setGeminiExplanation(null);
  };

  const handleGeminiExplain = async (finding: Finding) => {
    setIsExplaining(true);
    try {
      const explanation = await explainFindingsWithGemini([finding]);
      setGeminiExplanation(explanation);
    } catch (err) {
      setGeminiExplanation(`Failed to generate explanation: ${(err as Error).message}`);
    } finally {
      setIsExplaining(false);
    }
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* Material UI Responsive Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        mlStatus={mlStatus}
        overallTrustScore={stats?.overallTrustScore ?? 100}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      {/* Main Content Area */}
      <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Material UI Top Header / App Bar */}
        <Header
          currentTab={currentTab}
          onTabChange={setCurrentTab}
          onMobileDrawerToggle={() => setMobileOpen(!mobileOpen)}
          mlStatus={mlStatus}
          overallTrustScore={stats?.overallTrustScore ?? 100}
          hasDemoData={stats?.recentAnalyses.some((a) => a.isDemo)}
          onSeedDemo={handleSeedDemo}
          onClearDemo={handleClearDemo}
          isActionLoading={isActionLoading}
        />

        {/* Loading Indicator */}
        {isLoadingStats && (
          <LinearProgress
            color="primary"
            sx={{ height: 2, bgcolor: 'transparent' }}
          />
        )}

        {/* Page Content Container */}
        <Box
          component="main"
          sx={{
            flex: 1,
            width: '100%',
            maxWidth: 1380,
            mx: 'auto',
            px: { xs: 2, sm: 3, md: 4 },
            py: { xs: 2.5, sm: 3.5 },
          }}
        >
          {currentTab === 'dashboard' && (
            <DashboardPage
              stats={stats}
              isLoading={isLoadingStats}
              onNavigate={setCurrentTab}
              onSeedDemo={handleSeedDemo}
              onClearDemo={handleClearDemo}
              isActionLoading={isActionLoading}
            />
          )}

          {currentTab === 'evaluation' && <EvaluationPage />}

          {currentTab === 'dataset' && (
            <DatasetPage
              onFindingClick={handleFindingClick}
              onRefreshStats={loadPlatformData}
            />
          )}

          {currentTab === 'model' && (
            <ModelPage
              onFindingClick={handleFindingClick}
              onRefreshStats={loadPlatformData}
            />
          )}

          {currentTab === 'inference' && (
            <InferencePage onRefreshStats={loadPlatformData} />
          )}

          {currentTab === 'shift' && (
            <DistributionShiftPage
              onFindingClick={handleFindingClick}
              onRefreshStats={loadPlatformData}
            />
          )}

          {currentTab === 'history' && <HistoryPage />}

          {currentTab === 'config' && (
            <ConfigPage
              onSeedDemo={handleSeedDemo}
              onClearDemo={handleClearDemo}
              isActionLoading={isActionLoading}
            />
          )}

          {currentTab === 'methodology' && <MethodologyPage />}
        </Box>

        {/* Findings Inspector Drawer */}
        <FindingDrawer
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onGeminiExplain={handleGeminiExplain}
          isExplaining={isExplaining}
          geminiExplanation={geminiExplanation}
        />

        {/* Material UI Footer */}
        <Box
          component="footer"
          sx={{
            borderTop: '1px solid rgba(63, 63, 70, 0.4)',
            bgcolor: 'rgba(9, 9, 11, 0.95)',
            py: 2,
            px: 3,
            mt: 'auto',
          }}
        >
          <Box
            sx={{
              maxWidth: 1380,
              mx: 'auto',
              display: 'flex',
              flexDirection: { xs: 'column', sm: 'row' },
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 1,
            }}
          >
            <Typography
              variant="caption"
              sx={{
                color: '#71717a',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.72rem',
              }}
            >
              AI Integrity Assurance Platform • SIH 2026 Problem Statement SIH26228
            </Typography>
            <Typography
              variant="caption"
              sx={{
                color: '#10b981',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.72rem',
                fontWeight: 600,
              }}
            >
              FIPS 180-4 SHA-256 Provenance • Deterministic Risk Engine
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default function App() {
  return (
    <ThemeProvider theme={muiCyberTheme}>
      <CssBaseline />
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}
