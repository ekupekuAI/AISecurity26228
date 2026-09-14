import React from 'react';
import {
  AppBar,
  Toolbar,
  Box,
  Typography,
  IconButton,
  Chip,
  Button,
  Avatar,
  Tooltip,
} from '@mui/material';
import {
  Menu,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Trash2,
  Key,
} from 'lucide-react';
import { SIDEBAR_WIDTH } from './Sidebar.js';
import { NavTab } from './Navigation.js';
import { useAuth } from '../context/AuthContext.js';

interface HeaderProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  onMobileDrawerToggle: () => void;
  mlStatus: 'ONLINE' | 'OFFLINE' | 'CHECKING';
  overallTrustScore: number;
  hasDemoData?: boolean;
  onSeedDemo?: () => void;
  onClearDemo?: () => void;
  isActionLoading?: boolean;
}

const TAB_TITLES: Record<NavTab, { title: string; subtitle: string; section: string }> = {
  dashboard: {
    title: 'Integrity Assurance Monitor',
    subtitle: 'Real-time telemetry, risk gauges, and audit event stream',
    section: 'Platform Command',
  },
  evaluation: {
    title: 'ML Model Prediction Graphs & Analytics',
    subtitle: 'Comprehensive graphical representations of ML model predictions, output distributions, and confidence percentages',
    section: 'Platform Command',
  },
  dataset: {
    title: 'Dataset Forensics Lab',
    subtitle: 'Zip Slip defense, duplicate detection, class balance & corruption scans',
    section: 'Pipeline Assurance',
  },
  model: {
    title: 'Model Integrity & Backdoor Scanner',
    subtitle: 'Static binary opcode analysis, malicious payload & backdoor trigger inspection',
    section: 'Pipeline Assurance',
  },
  inference: {
    title: 'Inference Provenance & Tamper Lab',
    subtitle: 'Cryptographic SHA-256 canonical hashing & verification certificates',
    section: 'Pipeline Assurance',
  },
  shift: {
    title: 'Covariate Distribution Shift Monitor',
    subtitle: 'Statistical feature drift & sensor degradation surveillance',
    section: 'Pipeline Assurance',
  },
  history: {
    title: 'Audit Ledger & Quarantine Vault',
    subtitle: 'Tamper-evident chronological compliance & quarantine records',
    section: 'Audit & Governance',
  },
  config: {
    title: 'Platform System Configuration',
    subtitle: 'Assurance thresholds, API connectivity, and database persistence parameters',
    section: 'System & Spec',
  },
  methodology: {
    title: 'Defense Methodology & Compliance',
    subtitle: 'Mathematical formulas, threat taxonomy, and defense-in-depth architecture',
    section: 'System & Spec',
  },
};

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onTabChange,
  onMobileDrawerToggle,
  mlStatus,
  overallTrustScore,
  hasDemoData,
  onSeedDemo,
  onClearDemo,
  isActionLoading,
}) => {
  const { user } = useAuth();
  const currentInfo = TAB_TITLES[currentTab] || {
    title: 'AI Integrity Assurance',
    subtitle: 'Forensic Platform',
    section: 'Assurance',
  };

  return (
    <AppBar
      position="sticky"
      elevation={0}
      sx={{
        width: { md: `calc(100% - ${SIDEBAR_WIDTH}px)` },
        ml: { md: `${SIDEBAR_WIDTH}px` },
        bgcolor: 'rgba(9, 9, 11, 0.92)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(63, 63, 70, 0.4)',
        color: '#f4f4f5',
        zIndex: (theme) => theme.zIndex.drawer + 1,
      }}
    >
      <Toolbar sx={{ minHeight: { xs: 60, sm: 68 }, px: { xs: 2, sm: 3 } }}>
        {/* Mobile Hamburger Button */}
        <IconButton
          color="inherit"
          aria-label="open drawer"
          edge="start"
          onClick={onMobileDrawerToggle}
          sx={{ mr: 2, display: { md: 'none' }, color: '#d4d4d8' }}
        >
          <Menu size={22} />
        </IconButton>

        {/* Current Tab Title & Breadcrumb */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography
              variant="caption"
              sx={{
                color: '#10b981',
                fontSize: '0.68rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                fontFamily: '"JetBrains Mono", monospace',
              }}
            >
              {currentInfo.section}
            </Typography>
            <Typography variant="caption" sx={{ color: '#52525b' }}>
              /
            </Typography>
            <Typography
              variant="subtitle1"
              noWrap
              sx={{
                fontWeight: 700,
                fontSize: { xs: '0.85rem', sm: '1rem' },
                color: '#f4f4f5',
                letterSpacing: '-0.01em',
              }}
            >
              {currentInfo.title}
            </Typography>
          </Box>
          <Typography
            variant="caption"
            noWrap
            sx={{
              color: '#71717a',
              fontSize: '0.72rem',
              display: { xs: 'none', sm: 'block' },
              lineHeight: 1.2,
            }}
          >
            {currentInfo.subtitle}
          </Typography>
        </Box>

        {/* Right Header Actions & Indicators */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          {/* Quick Demo Controls */}
          {onSeedDemo && (
            <Tooltip title="Load pre-built corrupted dataset & model checkpoint for demo inspection">
              <Button
                variant="outlined"
                size="small"
                onClick={onSeedDemo}
                disabled={isActionLoading}
                startIcon={<Sparkles size={13} color="#c084fc" />}
                sx={{
                  display: { xs: 'none', lg: 'inline-flex' },
                  fontSize: '0.72rem',
                  textTransform: 'none',
                  borderColor: 'rgba(168, 85, 247, 0.4)',
                  color: '#e9d5ff',
                  bgcolor: 'rgba(168, 85, 247, 0.08)',
                  '&:hover': {
                    bgcolor: 'rgba(168, 85, 247, 0.16)',
                    borderColor: '#c084fc',
                  },
                }}
              >
                Load Demo Corpus
              </Button>
            </Tooltip>
          )}

          {hasDemoData && onClearDemo && (
            <Tooltip title="Purge demo assets from database">
              <Button
                variant="outlined"
                size="small"
                onClick={onClearDemo}
                disabled={isActionLoading}
                startIcon={<Trash2 size={13} color="#f87171" />}
                sx={{
                  display: { xs: 'none', lg: 'inline-flex' },
                  fontSize: '0.72rem',
                  textTransform: 'none',
                  borderColor: 'rgba(239, 68, 68, 0.4)',
                  color: '#fca5a5',
                  bgcolor: 'rgba(239, 68, 68, 0.08)',
                  '&:hover': {
                    bgcolor: 'rgba(239, 68, 68, 0.16)',
                    borderColor: '#f87171',
                  },
                }}
              >
                Purge Demo Data
              </Button>
            </Tooltip>
          )}

          {/* Engine Status Indicator (Desktop) */}
          <Box sx={{ display: { xs: 'none', sm: 'block' } }}>
            {mlStatus === 'ONLINE' ? (
              <Chip
                size="small"
                icon={<CheckCircle2 size={13} color="#10b981" />}
                label="Python ML"
                sx={{
                  height: 26,
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  bgcolor: 'rgba(16, 185, 129, 0.1)',
                  color: '#34d399',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  '& .MuiChip-icon': { ml: 0.75 },
                }}
              />
            ) : (
              <Chip
                size="small"
                icon={<AlertTriangle size={13} color="#fbbf24" />}
                label="Node Core"
                sx={{
                  height: 26,
                  fontSize: '0.7rem',
                  fontWeight: 600,
                  bgcolor: 'rgba(245, 158, 11, 0.1)',
                  color: '#fbbf24',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                  '& .MuiChip-icon': { ml: 0.75 },
                }}
              />
            )}
          </Box>

          {/* Platform Trust Index Chip */}
          <Chip
            size="small"
            icon={<ShieldCheck size={14} color={overallTrustScore >= 80 ? '#34d399' : '#fbbf24'} />}
            label={`Trust: ${overallTrustScore}/100`}
            sx={{
              height: 28,
              fontSize: '0.72rem',
              fontWeight: 800,
              fontFamily: '"JetBrains Mono", monospace',
              bgcolor:
                overallTrustScore >= 80
                  ? 'rgba(16, 185, 129, 0.12)'
                  : overallTrustScore >= 60
                  ? 'rgba(245, 158, 11, 0.12)'
                  : 'rgba(239, 68, 68, 0.12)',
              color:
                overallTrustScore >= 80 ? '#34d399' : overallTrustScore >= 60 ? '#fbbf24' : '#f87171',
              border: `1px solid ${
                overallTrustScore >= 80
                  ? 'rgba(16, 185, 129, 0.4)'
                  : overallTrustScore >= 60
                  ? 'rgba(245, 158, 11, 0.4)'
                  : 'rgba(239, 68, 68, 0.4)'
              }`,
              '& .MuiChip-icon': { ml: 0.75 },
            }}
          />

          {/* Defense Standard Badge */}
          <Chip
            size="small"
            label="ISO/IEC 42001 &amp; FIPS 180-4"
            sx={{
              display: { xs: 'none', md: 'inline-flex' },
              height: 26,
              fontSize: '0.68rem',
              fontWeight: 600,
              fontFamily: '"JetBrains Mono", monospace',
              bgcolor: 'rgba(24, 24, 27, 0.8)',
              color: '#a1a1aa',
              border: '1px solid rgba(63, 63, 70, 0.5)',
            }}
          />
        </Box>
      </Toolbar>
    </AppBar>
  );
};
