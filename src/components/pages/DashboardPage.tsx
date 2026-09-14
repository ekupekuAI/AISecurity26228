import React from 'react';
import {
  Box,
  Card,
  Typography,
  Button,
  LinearProgress,
  Chip,
  Divider,
  Paper,
} from '@mui/material';
import {
  ShieldCheck,
  ShieldAlert,
  Database,
  Cpu,
  Fingerprint,
  TrendingUp,
  AlertOctagon,
  FileText,
  Clock,
  ExternalLink,
  Trash2,
  Sparkles,
  ArrowRight,
  LineChart,
  CheckCircle2,
} from 'lucide-react';
import { PlatformStats } from '../../types.js';
import { MetricCard } from '../MetricCard.js';
import { StatusBadge } from '../StatusBadge.js';
import { SeverityBadge } from '../SeverityBadge.js';
import { NavTab } from '../Navigation.js';

interface DashboardPageProps {
  stats: PlatformStats | null;
  isLoading: boolean;
  onNavigate: (tab: NavTab) => void;
  onSeedDemo: () => void;
  onClearDemo: () => void;
  isActionLoading: boolean;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  stats,
  isLoading,
  onNavigate,
  onSeedDemo,
  onClearDemo,
  isActionLoading,
}) => {
  if (isLoading && !stats) {
    return (
      <Box sx={{ display: 'flex', minHeight: 400, alignItems: 'center', justifyContent: 'center' }}>
        <Box sx={{ textAlign: 'center' }}>
          <LinearProgress
            color="primary"
            sx={{ width: 140, height: 4, borderRadius: 2, mb: 2, mx: 'auto' }}
          />
          <Typography
            variant="caption"
            sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#a1a1aa' }}
          >
            Loading AI Assurance telemetry stream...
          </Typography>
        </Box>
      </Box>
    );
  }

  const trustScore = stats?.overallTrustScore ?? 100;
  const datasetRisk = stats?.datasetRisk ?? 0;
  const modelRisk = stats?.modelRisk ?? 0;
  const inferenceRisk = stats?.inferenceIntegrityRisk ?? 0;
  const shiftRisk = stats?.distributionShiftRisk ?? 0;
  const hasDemo = stats?.recentAnalyses.some((a) => a.isDemo) ?? false;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {/* Top Banner / SIH Overview Card */}
      <Card
        elevation={0}
        sx={{
          borderRadius: '16px',
          border: '1px solid rgba(63, 63, 70, 0.4)',
          background:
            'radial-gradient(ellipse at top left, rgba(16, 185, 129, 0.08) 0%, rgba(9, 9, 11, 0.95) 70%)',
          p: { xs: 2.5, sm: 3 },
        }}
      >
        <Box
          sx={{
            display: 'flex',
            flexDirection: { xs: 'column', md: 'row' },
            alignItems: { xs: 'flex-start', md: 'center' },
            justifyContent: 'space-between',
            gap: 2.5,
          }}
        >
          <Box sx={{ maxWidth: 720 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
              <Box
                sx={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  bgcolor: '#10b981',
                  boxShadow: '0 0 10px #10b981',
                }}
              />
              <Typography
                variant="h6"
                sx={{ fontWeight: 800, color: '#f4f4f5', letterSpacing: '-0.01em' }}
              >
                Pipeline Trust &amp; Integrity Assurance Monitor
              </Typography>
            </Box>
            <Typography variant="body2" sx={{ color: '#a1a1aa', lineHeight: 1.6, fontSize: '0.82rem' }}>
              Continuous cryptographic provenance, dataset poisoning detection, Trojan trigger
              inspection, and distribution shift surveillance for mission-critical computer vision models.
            </Typography>
          </Box>

          {/* Quick Actions in Banner */}
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5 }}>
            <Button
              variant="contained"
              color="primary"
              size="small"
              onClick={() => onNavigate('dataset')}
              startIcon={<Database size={15} />}
              sx={{
                fontSize: '0.78rem',
                fontWeight: 700,
                textTransform: 'none',
                bgcolor: '#059669',
                color: '#ffffff',
                boxShadow: '0 2px 10px rgba(5, 150, 105, 0.3)',
                '&:hover': { bgcolor: '#047857' },
              }}
            >
              Scan Dataset
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => onNavigate('model')}
              startIcon={<Cpu size={15} />}
              sx={{
                fontSize: '0.78rem',
                fontWeight: 600,
                textTransform: 'none',
                borderColor: 'rgba(63, 63, 70, 0.7)',
                color: '#e4e4e7',
                bgcolor: 'rgba(24, 24, 27, 0.5)',
                '&:hover': { borderColor: '#a1a1aa', bgcolor: 'rgba(39, 39, 42, 0.6)' },
              }}
            >
              Inspect Model
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => onNavigate('inference')}
              startIcon={<Fingerprint size={15} />}
              sx={{
                fontSize: '0.78rem',
                fontWeight: 600,
                textTransform: 'none',
                borderColor: 'rgba(63, 63, 70, 0.7)',
                color: '#e4e4e7',
                bgcolor: 'rgba(24, 24, 27, 0.5)',
                '&:hover': { borderColor: '#a1a1aa', bgcolor: 'rgba(39, 39, 42, 0.6)' },
              }}
            >
              Provenance Lab
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => onNavigate('evaluation')}
              startIcon={<LineChart size={15} />}
              sx={{
                fontSize: '0.78rem',
                fontWeight: 700,
                textTransform: 'none',
                borderColor: 'rgba(239, 68, 68, 0.6)',
                color: '#fca5a5',
                bgcolor: 'rgba(239, 68, 68, 0.1)',
                '&:hover': { borderColor: '#ef4444', bgcolor: 'rgba(239, 68, 68, 0.2)' },
              }}
            >
              Predicted Graphs &amp; Eval
            </Button>
          </Box>
        </Box>

        {/* Pipeline State & Seed Controls Bar */}
        <Divider sx={{ my: 2, borderColor: 'rgba(63, 63, 70, 0.4)' }} />

        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 1.5,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Typography
              variant="caption"
              sx={{
                color: '#71717a',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.72rem',
              }}
            >
              Pipeline State:
            </Typography>
            {hasDemo ? (
              <Chip
                size="small"
                icon={<AlertOctagon size={13} color="#f59e0b" />}
                label="Active (Demo corpus & anomalies loaded)"
                sx={{
                  height: 22,
                  fontSize: '0.68rem',
                  fontWeight: 600,
                  bgcolor: 'rgba(245, 158, 11, 0.12)',
                  color: '#fbbf24',
                  border: '1px solid rgba(245, 158, 11, 0.3)',
                }}
              />
            ) : (
              <Chip
                size="small"
                icon={<ShieldCheck size={13} color="#10b981" />}
                label="Live Production (Clean database state)"
                sx={{
                  height: 22,
                  fontSize: '0.68rem',
                  fontWeight: 600,
                  bgcolor: 'rgba(16, 185, 129, 0.12)',
                  color: '#34d399',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                }}
              />
            )}
          </Box>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={onSeedDemo}
              disabled={isActionLoading}
              startIcon={<Sparkles size={13} color="#c084fc" />}
              sx={{
                fontSize: '0.72rem',
                textTransform: 'none',
                borderColor: 'rgba(168, 85, 247, 0.4)',
                color: '#e9d5ff',
                bgcolor: 'rgba(168, 85, 247, 0.08)',
                '&:hover': { borderColor: '#c084fc', bgcolor: 'rgba(168, 85, 247, 0.15)' },
              }}
            >
              Load Demo Corpus
            </Button>
            {hasDemo && (
              <Button
                size="small"
                variant="outlined"
                onClick={onClearDemo}
                disabled={isActionLoading}
                startIcon={<Trash2 size={13} color="#f87171" />}
                sx={{
                  fontSize: '0.72rem',
                  textTransform: 'none',
                  borderColor: 'rgba(239, 68, 68, 0.4)',
                  color: '#fca5a5',
                  bgcolor: 'rgba(239, 68, 68, 0.08)',
                  '&:hover': { borderColor: '#f87171', bgcolor: 'rgba(239, 68, 68, 0.15)' },
                }}
              >
                Purge Demo Data
              </Button>
            )}
          </Box>
        </Box>
      </Card>

      {/* Core Assurance Pillar Metrics Grid */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr', lg: '1fr 1fr 1fr 1fr' },
          gap: 2,
        }}
      >
        {/* Overall Trust Score Gauge */}
        <Card
          elevation={0}
          sx={{
            p: 2,
            borderRadius: '12px',
            bgcolor: 'rgba(24, 24, 27, 0.7)',
            border: '1px solid rgba(63, 63, 70, 0.5)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            transition: 'all 0.2s',
            '&:hover': { borderColor: 'rgba(113, 113, 122, 0.7)', transform: 'translateY(-1px)' },
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography
              variant="caption"
              sx={{
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                color: '#a1a1aa',
                fontSize: '0.7rem',
              }}
            >
              Pipeline Trust Score
            </Typography>
            <ShieldCheck
              size={18}
              color={
                trustScore >= 80 ? '#34d399' : trustScore >= 60 ? '#fbbf24' : '#f87171'
              }
            />
          </Box>

          <Box sx={{ my: 1.5 }}>
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
              <Typography
                variant="h4"
                sx={{
                  fontFamily: '"JetBrains Mono", monospace',
                  fontWeight: 800,
                  fontSize: '2rem',
                  lineHeight: 1,
                  color:
                    trustScore >= 80 ? '#34d399' : trustScore >= 60 ? '#fbbf24' : '#f87171',
                }}
              >
                {trustScore}
              </Typography>
              <Typography
                variant="caption"
                sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#71717a' }}
              >
                / 100
              </Typography>
            </Box>
            <Typography variant="caption" sx={{ color: '#71717a', fontSize: '0.68rem', mt: 0.5, display: 'block' }}>
              Formula: 100 - (0.35·D + 0.35·M + 0.15·I + 0.15·S)
            </Typography>
          </Box>

          <Box
            sx={{
              height: 5,
              width: '100%',
              borderRadius: 3,
              bgcolor: 'rgba(63, 63, 70, 0.5)',
              overflow: 'hidden',
            }}
          >
            <Box
              sx={{
                height: '100%',
                width: `${trustScore}%`,
                bgcolor:
                  trustScore >= 80 ? '#10b981' : trustScore >= 60 ? '#f59e0b' : '#ef4444',
                transition: 'width 0.5s ease',
              }}
            />
          </Box>
        </Card>

        {/* Dataset Risk */}
        <MetricCard
          label="Dataset Risk"
          value={`${datasetRisk}`}
          subValue="/ 100 (35% weight)"
          icon={Database}
          variant={datasetRisk > 50 ? 'danger' : datasetRisk > 20 ? 'warning' : 'default'}
        />

        {/* Model Risk */}
        <MetricCard
          label="Model Integrity Risk"
          value={`${modelRisk}`}
          subValue="/ 100 (35% weight)"
          icon={Cpu}
          variant={modelRisk > 50 ? 'danger' : modelRisk > 20 ? 'warning' : 'default'}
        />

        {/* Inference / Shift Combined Risk */}
        <MetricCard
          label="Inference & Shift Risk"
          value={`${Math.round((inferenceRisk * 0.5 + shiftRisk * 0.5) * 10) / 10}`}
          subValue={`Inf: ${inferenceRisk} | Shift: ${shiftRisk}`}
          icon={Fingerprint}
          variant={inferenceRisk > 20 || shiftRisk > 30 ? 'warning' : 'default'}
        />
      </Box>

      {/* Asset Inventory Overview Strip */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr 1fr' },
          gap: 2,
        }}
      >
        <Paper
          elevation={0}
          sx={{
            p: 2,
            borderRadius: '12px',
            bgcolor: 'rgba(24, 24, 27, 0.4)',
            border: '1px solid rgba(63, 63, 70, 0.4)',
            display: 'flex',
            alignItems: 'center',
            gap: 2,
          }}
        >
          <Box
            sx={{
              p: 1.25,
              borderRadius: '8px',
              bgcolor: 'rgba(39, 39, 42, 0.8)',
              color: '#d4d4d8',
              display: 'flex',
            }}
          >
            <FileText size={20} />
          </Box>
          <Box>
            <Typography
              variant="caption"
              sx={{
                color: '#a1a1aa',
                textTransform: 'uppercase',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.68rem',
                display: 'block',
              }}
            >
              Analyzed Pipeline Assets
            </Typography>
            <Typography
              variant="h6"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                fontWeight: 800,
                color: '#f4f4f5',
                lineHeight: 1.1,
              }}
            >
              {stats?.analyzedAssetsCount ?? 0}
            </Typography>
          </Box>
        </Paper>

        <Paper
          elevation={0}
          sx={{
            p: 2,
            borderRadius: '12px',
            bgcolor: 'rgba(24, 24, 27, 0.4)',
            border: '1px solid rgba(63, 63, 70, 0.4)',
            display: 'flex',
            alignItems: 'center',
            gap: 2,
          }}
        >
          <Box
            sx={{
              p: 1.25,
              borderRadius: '8px',
              bgcolor: 'rgba(245, 158, 11, 0.15)',
              color: '#fbbf24',
              display: 'flex',
            }}
          >
            <ShieldAlert size={20} />
          </Box>
          <Box>
            <Typography
              variant="caption"
              sx={{
                color: '#a1a1aa',
                textTransform: 'uppercase',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.68rem',
                display: 'block',
              }}
            >
              Suspicious Findings
            </Typography>
            <Typography
              variant="h6"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                fontWeight: 800,
                color: '#fcd34d',
                lineHeight: 1.1,
              }}
            >
              {stats?.suspiciousFindingsCount ?? 0}
            </Typography>
          </Box>
        </Paper>

        <Paper
          elevation={0}
          sx={{
            p: 2,
            borderRadius: '12px',
            bgcolor: 'rgba(24, 24, 27, 0.4)',
            border: '1px solid rgba(63, 63, 70, 0.4)',
            display: 'flex',
            alignItems: 'center',
            gap: 2,
          }}
        >
          <Box
            sx={{
              p: 1.25,
              borderRadius: '8px',
              bgcolor: 'rgba(239, 68, 68, 0.15)',
              color: '#f87171',
              display: 'flex',
            }}
          >
            <AlertOctagon size={20} />
          </Box>
          <Box>
            <Typography
              variant="caption"
              sx={{
                color: '#a1a1aa',
                textTransform: 'uppercase',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.68rem',
                display: 'block',
              }}
            >
              Quarantined Assets
            </Typography>
            <Typography
              variant="h6"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                fontWeight: 800,
                color: '#fca5a5',
                lineHeight: 1.1,
              }}
            >
              {stats?.quarantinedAssetsCount ?? 0}
            </Typography>
          </Box>
        </Paper>
      </Box>

      {/* Two Column Layout: Recent Analyses & Security Audit Stream */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
          gap: 3,
        }}
      >
        {/* Recent Analyses Card */}
        <Card
          elevation={0}
          sx={{
            p: 2.5,
            borderRadius: '14px',
            bgcolor: 'rgba(24, 24, 27, 0.5)',
            border: '1px solid rgba(63, 63, 70, 0.4)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              pb: 1.75,
              borderBottom: '1px solid rgba(63, 63, 70, 0.4)',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <FileText size={18} color="#34d399" />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#f4f4f5' }}>
                Recent Pipeline Analyses
              </Typography>
            </Box>
            <Button
              size="small"
              onClick={() => onNavigate('history')}
              endIcon={<ExternalLink size={13} />}
              sx={{
                fontSize: '0.72rem',
                textTransform: 'none',
                color: '#34d399',
                '&:hover': { bgcolor: 'rgba(16, 185, 129, 0.08)' },
              }}
            >
              View all
            </Button>
          </Box>

          <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 1.25 }}>
            {stats?.recentAnalyses && stats.recentAnalyses.length > 0 ? (
              stats.recentAnalyses.slice(0, 5).map((analysis) => (
                <Box
                  key={analysis.id}
                  sx={{
                    p: 1.25,
                    borderRadius: '8px',
                    bgcolor: 'rgba(18, 18, 20, 0.6)',
                    border: '1px solid rgba(63, 63, 70, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 1.5,
                  }}
                >
                  <Box sx={{ minWidth: 0, flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography
                        variant="body2"
                        noWrap
                        sx={{ fontWeight: 600, color: '#f4f4f5', fontSize: '0.8rem' }}
                      >
                        {analysis.name}
                      </Typography>
                      {analysis.isDemo && (
                        <Chip
                          size="small"
                          label="DEMO"
                          sx={{
                            height: 16,
                            fontSize: '0.58rem',
                            fontFamily: 'monospace',
                            bgcolor: 'rgba(245, 158, 11, 0.15)',
                            color: '#fbbf24',
                            border: '1px solid rgba(245, 158, 11, 0.3)',
                          }}
                        />
                      )}
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.25 }}>
                      <Typography
                        variant="caption"
                        sx={{
                          fontFamily: '"JetBrains Mono", monospace',
                          color: '#a1a1aa',
                          fontSize: '0.68rem',
                        }}
                      >
                        {analysis.type}
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#52525b' }}>
                        •
                      </Typography>
                      <Typography
                        variant="caption"
                        noWrap
                        sx={{
                          fontFamily: '"JetBrains Mono", monospace',
                          color: '#71717a',
                          fontSize: '0.65rem',
                          maxWidth: 160,
                        }}
                      >
                        {analysis.sha256}
                      </Typography>
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <StatusBadge status={analysis.status} size="sm" />
                    <Typography
                      variant="caption"
                      sx={{
                        fontFamily: '"JetBrains Mono", monospace',
                        fontWeight: 700,
                        color: analysis.risk > 50 ? '#f87171' : analysis.risk > 20 ? '#fbbf24' : '#34d399',
                        minWidth: 28,
                        textAlign: 'right',
                      }}
                    >
                      {analysis.risk}
                    </Typography>
                  </Box>
                </Box>
              ))
            ) : (
              <Box sx={{ py: 6, textAlign: 'center', color: '#71717a' }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>
                  No analyses recorded yet. Scan a dataset or inspect a model to begin.
                </Typography>
              </Box>
            )}
          </Box>
        </Card>

        {/* Security Audit Stream Card */}
        <Card
          elevation={0}
          sx={{
            p: 2.5,
            borderRadius: '14px',
            bgcolor: 'rgba(24, 24, 27, 0.5)',
            border: '1px solid rgba(63, 63, 70, 0.4)',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              pb: 1.75,
              borderBottom: '1px solid rgba(63, 63, 70, 0.4)',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Clock size={18} color="#c084fc" />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#f4f4f5' }}>
                Security Audit Stream
              </Typography>
            </Box>
            <Chip
              size="small"
              label="Append-Only Ledger"
              sx={{
                height: 20,
                fontSize: '0.62rem',
                fontFamily: '"JetBrains Mono", monospace',
                bgcolor: 'rgba(168, 85, 247, 0.1)',
                color: '#d8b4fe',
                border: '1px solid rgba(168, 85, 247, 0.3)',
              }}
            />
          </Box>

          <Box
            sx={{
              mt: 2,
              display: 'flex',
              flexDirection: 'column',
              gap: 1.25,
              maxHeight: 320,
              overflowY: 'auto',
              pr: 0.5,
            }}
          >
            {stats?.recentAuditEvents && stats.recentAuditEvents.length > 0 ? (
              stats.recentAuditEvents.slice(0, 6).map((evt) => (
                <Paper
                  key={evt.id}
                  elevation={0}
                  sx={{
                    p: 1.5,
                    borderRadius: '8px',
                    bgcolor: 'rgba(18, 18, 20, 0.7)',
                    border: '1px solid rgba(63, 63, 70, 0.3)',
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                    <Typography
                      variant="caption"
                      sx={{
                        fontWeight: 700,
                        color: '#e4e4e7',
                        fontFamily: '"JetBrains Mono", monospace',
                        fontSize: '0.72rem',
                      }}
                    >
                      {evt.eventType}
                    </Typography>
                    <SeverityBadge severity={evt.severity} size="sm" />
                  </Box>
                  <Typography variant="body2" sx={{ color: '#a1a1aa', fontSize: '0.76rem', mb: 0.75 }}>
                    {evt.description}
                  </Typography>
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      color: '#71717a',
                      fontSize: '0.68rem',
                      fontFamily: '"JetBrains Mono", monospace',
                    }}
                  >
                    <Typography variant="caption" noWrap sx={{ maxWidth: 200, color: '#71717a', fontSize: '0.68rem' }}>
                      {evt.assetName}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#71717a', fontSize: '0.68rem' }}>
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </Typography>
                  </Box>
                </Paper>
              ))
            ) : (
              <Box sx={{ py: 6, textAlign: 'center', color: '#71717a' }}>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>
                  No audit events recorded in current session ledger.
                </Typography>
              </Box>
            )}
          </Box>
        </Card>
      </Box>
    </Box>
  );
};
