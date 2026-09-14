import React from 'react';
import {
  ShieldAlert,
  Database,
  Cpu,
  Fingerprint,
  TrendingUp,
  History,
  FileSearch,
  Settings,
  BookOpen,
  Activity,
  LineChart,
  CheckCircle2,
  AlertTriangle,
  Home,
  User,
  LogOut,
  Key,
} from 'lucide-react';
import {
  Box,
  Chip,
  Avatar,
  Button,
  Tooltip,
} from '@mui/material';
import { useAuth } from '../context/AuthContext.js';

export type NavTab =
  | 'dashboard'
  | 'evaluation'
  | 'dataset'
  | 'model'
  | 'inference'
  | 'shift'
  | 'history'
  | 'config'
  | 'methodology';

interface NavigationProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  mlStatus: 'ONLINE' | 'OFFLINE' | 'CHECKING';
  overallTrustScore: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  currentTab,
  onTabChange,
  mlStatus,
  overallTrustScore,
}) => {
  const { user, logout } = useAuth();

  const tabs = [
    { id: 'dashboard' as NavTab, label: 'Mission Command', icon: Activity },
    { id: 'evaluation' as NavTab, label: 'Model Evaluation & Graphs', icon: LineChart },
    { id: 'dataset' as NavTab, label: 'Dataset Forensics', icon: Database },
    { id: 'model' as NavTab, label: 'Model Integrity', icon: Cpu },
    { id: 'inference' as NavTab, label: 'Inference Provenance', icon: Fingerprint },
    { id: 'shift' as NavTab, label: 'Distribution Shift', icon: TrendingUp },
    { id: 'history' as NavTab, label: 'Audit History', icon: History },
    { id: 'config' as NavTab, label: 'System Config', icon: Settings },
    { id: 'methodology' as NavTab, label: 'Methodology', icon: BookOpen },
  ];

  return (
    <header className="border-b border-zinc-800 bg-zinc-950/95 backdrop-blur sticky top-0 z-40">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between gap-4">
          {/* Brand & Subtitle */}
          <div
            className="flex items-center gap-3 cursor-pointer"
            onClick={() => onTabChange('dashboard')}
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-zinc-100 tracking-tight text-sm sm:text-base">
                  AI Integrity Assurance Platform
                </span>
                <Chip
                  label="SIH26228"
                  size="small"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.65rem',
                    height: 20,
                    bgcolor: 'rgba(16, 185, 129, 0.1)',
                    color: '#34d399',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                  }}
                />
              </div>
              <p className="text-[11px] text-zinc-400 font-mono tracking-tight hidden sm:block">
                Computer-Vision Pipeline Assurance &amp; Forensic Security
              </p>
            </div>
          </div>

          {/* Engine Status, Platform Trust Pill & Auth Avatar */}
          <div className="flex items-center gap-2.5">
            {/* Engine Indicator */}
            <div className="hidden md:flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-2.5 py-1 text-xs font-mono">
              <span className="text-zinc-400 text-[11px]">Engine:</span>
              {mlStatus === 'ONLINE' ? (
                <span className="flex items-center gap-1 text-emerald-400 font-medium">
                  <CheckCircle2 className="h-3.5 w-3.5" /> Python ML Active
                </span>
              ) : mlStatus === 'CHECKING' ? (
                <span className="flex items-center gap-1 text-zinc-400">Checking...</span>
              ) : (
                <span className="flex items-center gap-1 text-amber-400 font-medium" title="Node.js Internal Deterministic Engine Active">
                  <AlertTriangle className="h-3.5 w-3.5" /> Standalone Node
                </span>
              )}
            </div>

            {/* Trust Index Gauge */}
            <div className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/80 px-3 py-1 text-xs font-mono">
              <span className="text-zinc-400 text-[11px]">Trust Index:</span>
              <span
                className={`font-bold ${
                  overallTrustScore >= 80
                    ? 'text-emerald-400'
                    : overallTrustScore >= 60
                    ? 'text-amber-400'
                    : 'text-rose-400'
                }`}
              >
                {overallTrustScore}/100
              </span>
            </div>

            {/* User Profile / Login Clearance Chip */}
            {user ? (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Tooltip title={`${user.name} (${user.role}) - Click to manage session`}>
                  <Chip
                    avatar={
                      <Avatar sx={{ bgcolor: 'primary.dark', color: '#fff', fontSize: '0.75rem', fontWeight: 700 }}>
                        {user.name.charAt(0)}
                      </Avatar>
                    }
                    label={user.name.split(' ')[0]}
                    onClick={() => onTabChange('dashboard')}
                    variant="outlined"
                    size="small"
                    sx={{
                      cursor: 'pointer',
                      borderColor: 'rgba(16, 185, 129, 0.3)',
                      bgcolor: 'rgba(16, 185, 129, 0.05)',
                      color: '#f4f4f5',
                      height: 32,
                    }}
                  />
                </Tooltip>
                <Tooltip title="Log out current session">
                  <Button
                    size="small"
                    color="inherit"
                    onClick={logout}
                    sx={{ minWidth: 32, p: 0.5, color: 'text.secondary', '&:hover': { color: 'error.main' } }}
                  >
                    <LogOut size={16} />
                  </Button>
                </Tooltip>
              </Box>
            ) : null}
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <nav className="flex space-x-1 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-zinc-800">
          {tabs.map(tab => {
            const Icon = tab.icon;
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`nav-${tab.id}`}
                onClick={() => onTabChange(tab.id)}
                className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-zinc-800 text-zinc-100 border border-zinc-700 shadow-sm'
                    : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-emerald-400' : 'text-zinc-500'}`} />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
