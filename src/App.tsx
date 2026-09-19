import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import { AuthProvider, useAuth } from './context/AuthContext.js';
import { WorkbenchProvider } from './context/WorkbenchContext.js';
import { LoginPage } from './components/LoginPage.js';
import { FindingInspector, Sidebar, TopBar, type NavTab } from './components/Shell.js';
import { DashboardPage } from './components/pages/DashboardPage.js';
import { AnalyticsPage } from './components/pages/AnalyticsPage.js';
import { SentinelPage } from './components/pages/SentinelPage.js';
import { AibomPage } from './components/pages/AibomPage.js';
import { DatasetPage } from './components/pages/DatasetPage.js';
import { ModelPage } from './components/pages/ModelPage.js';
import { InferencePage } from './components/pages/InferencePage.js';
import { ShiftPage } from './components/pages/ShiftPage.js';
import { HistoryPage } from './components/pages/HistoryPage.js';
import { ConfigPage } from './components/pages/ConfigPage.js';
import { MethodologyPage } from './components/pages/MethodologyPage.js';
import type { Finding, PlatformStats } from './types.js';
import { acknowledgeFinding, fetchEngineHealth, fetchPlatformStats } from './api/client.js';
import { Badge, Spinner, ToastStack, type ToastMessage } from './ui/primitives.js';

const PAGE_META: Record<NavTab, { title: string; subtitle: string }> = {
  dashboard: {
    title: 'Assurance monitor',
    subtitle: 'The overall verdict, live risk scores and any open findings, in one place.',
  },
  analytics: {
    title: 'Analytics',
    subtitle: 'Risk trends and score graphs across every check run on this node.',
  },
  sentinel: {
    title: 'Live monitoring',
    subtitle: 'Background monitors that watch for threats, tampering and unusual activity.',
  },
  dataset: {
    title: 'Dataset integrity',
    subtitle: 'Check a dataset for copied images, wrong labels, hidden triggers and odd samples.',
  },
  model: {
    title: 'Model integrity',
    subtitle: 'Check a model file for unsafe code, tampering and hidden backdoors.',
  },
  inference: {
    title: 'Inference provenance',
    subtitle: 'Seal a prediction so any later tampering or replay can be detected.',
  },
  shift: {
    title: 'Distribution shift',
    subtitle: 'Spot when incoming data drifts — and whether it is the environment or an attack.',
  },
  history: { title: 'Audit & reports', subtitle: 'The tamper-proof log, past checks and the signed report.' },
  aibom: { title: 'Model passport', subtitle: 'Issue and verify a signed passport (AI-BOM) for a model or dataset.' },
  config: { title: 'Node settings', subtitle: 'Engine connection, signing keys and how this node is deployed.' },
  methodology: { title: 'Methodology', subtitle: 'How each check works, its exact thresholds, and what it cannot catch.' },
};

function Console() {
  const { user, can, notice } = useAuth();
  const [tab, setTab] = useState<NavTab>('dashboard');
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [engineStatus, setEngineStatus] = useState('CHECKING');
  const [navOpen, setNavOpen] = useState(false);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const pushToast = useCallback((tone: ToastMessage['tone'], title: string, detail?: string) => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, tone, title, detail }]);
    setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), 9000);
  }, []);

  const refresh = useCallback(async () => {
    setLoadingStats(true);
    try {
      const [statsResult, health] = await Promise.all([
        fetchPlatformStats().catch(() => null),
        fetchEngineHealth().catch(() => null),
      ]);
      if (statsResult) setStats(statsResult);
      setEngineStatus(health?.status ?? 'OFFLINE');
    } finally {
      setLoadingStats(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Guarded against a repeat: StrictMode runs effects twice in development, and two
  // identical toasts stacked on top of each other looks like a bug to anyone watching.
  const noticeShown = useRef<string | null>(null);
  useEffect(() => {
    if (!notice || noticeShown.current === notice) return;
    noticeShown.current = notice;
    pushToast('info', 'Session notice', notice);
  }, [notice, pushToast]);

  // Scroll to the top on navigation; landing mid-page after a tab change is disorienting.
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [tab]);

  const acknowledge = useCallback(
    async (target: Finding) => {
      try {
        await acknowledgeFinding(target.id);
        pushToast('ok', 'Finding acknowledged', `${target.findingId} recorded as reviewed.`);
        setFinding(null);
        void refresh();
      } catch (error) {
        pushToast('error', 'Could not acknowledge', error instanceof Error ? error.message : undefined);
      }
    },
    [pushToast, refresh]
  );

  const meta = PAGE_META[tab];

  const headerActions = useMemo(
    () => (
      <>
        {engineStatus !== 'ONLINE' && (
          <Badge tone="warn" pulse>
            degraded
          </Badge>
        )}
        {user?.isDemoAccount && <Badge tone="warn">read-only</Badge>}
        {loadingStats && <Spinner className="h-3.5 w-3.5 text-[var(--color-ink-dim)]" />}
      </>
    ),
    [engineStatus, user?.isDemoAccount, loadingStats]
  );

  const shared = { onFindingClick: setFinding, onRefresh: refresh, pushToast };

  return (
    <WorkbenchProvider pushToast={pushToast} onComplete={refresh}>
    <div className="flex min-h-screen">
      <Sidebar
        current={tab}
        onNavigate={setTab}
        engineStatus={engineStatus}
        trustScore={stats?.overallTrustScore ?? 100}
        open={navOpen}
        onClose={() => setNavOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar title={meta.title} subtitle={meta.subtitle} onMenu={() => setNavOpen(true)} actions={headerActions} />

        {engineStatus !== 'ONLINE' && engineStatus !== 'CHECKING' && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="overflow-hidden border-b border-amber-500/25 bg-amber-500/8"
          >
            <p className="px-4 py-2.5 text-[11.5px] leading-relaxed text-amber-200/90 lg:px-6">
              Assurance engine unreachable — running the degraded gateway fallback. Deep detectors did
              not run, so results are marked degraded and cannot be ACCEPTED.
            </p>
          </motion.div>
        )}

        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-5 lg:px-6 lg:py-7">
          <AnimatePresence mode="wait">
            <motion.div
              key={tab}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.26, ease: [0.16, 1, 0.3, 1] }}
            >
              {tab === 'dashboard' && (
                <DashboardPage stats={stats} loading={loadingStats} onNavigate={setTab} {...shared} />
              )}
              {tab === 'analytics' && <AnalyticsPage stats={stats} loading={loadingStats} {...shared} />}
              {tab === 'sentinel' && <SentinelPage {...shared} />}
              {tab === 'dataset' && <DatasetPage {...shared} />}
              {tab === 'model' && <ModelPage {...shared} />}
              {tab === 'inference' && <InferencePage {...shared} />}
              {tab === 'shift' && <ShiftPage {...shared} />}
              {tab === 'history' && <HistoryPage {...shared} />}
              {tab === 'aibom' && <AibomPage {...shared} />}
              {tab === 'config' && <ConfigPage {...shared} />}
              {tab === 'methodology' && <MethodologyPage />}
            </motion.div>
          </AnimatePresence>
        </main>

        <footer className="border-t border-[var(--color-border)] px-4 py-3.5 lg:px-6">
          <div className="mx-auto flex max-w-[1400px] flex-col items-center justify-between gap-1.5 sm:flex-row">
            <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              SIH26228 · {user?.name} · {user?.role.replace(/_/g, ' ').toLowerCase()}
            </p>
            <p className="mono text-[10px] uppercase tracking-wider text-[var(--color-ink-dim)]">
              RFC 8785 · Ed25519 · air-gapped
            </p>
          </div>
        </footer>
      </div>

      <FindingInspector
        finding={finding}
        onClose={() => setFinding(null)}
        onAcknowledge={can('finding:acknowledge') ? acknowledge : undefined}
      />
      <ToastStack toasts={toasts} onDismiss={(id) => setToasts((c) => c.filter((t) => t.id !== id))} />
    </div>
    </WorkbenchProvider>
  );
}

function AuthGate() {
  const { status, isAuthenticated, user } = useAuth();

  if (status === 'checking') {
    return (
      <div className="grid min-h-screen place-items-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.94 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex flex-col items-center gap-3"
        >
          <Spinner className="h-6 w-6 text-[var(--color-accent-bright)]" />
          <p className="mono text-[10px] uppercase tracking-[0.2em] text-[var(--color-ink-dim)]">
            verifying session
          </p>
        </motion.div>
      </div>
    );
  }

  if (!isAuthenticated || !user) return <LoginPage />;
  return <Console />;
}

export default function App() {
  // reducedMotion="user" makes every Framer Motion animation honour the OS "reduce motion"
  // setting. The CSS @media block only stops CSS animations; the console's motion is almost
  // all JS-driven, so without this an operator who asked for calm still gets the full motion.
  return (
    <MotionConfig reducedMotion="user">
      <AuthProvider>
        <AuthGate />
      </AuthProvider>
    </MotionConfig>
  );
}

export type { NavTab };
