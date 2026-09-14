import React from 'react';
import {
  Drawer,
  Box,
  Typography,
  IconButton,
  Button,
  Divider,
  Paper,
  Chip,
  CircularProgress,
} from '@mui/material';
import { X, ShieldAlert, Cpu, Sparkles } from 'lucide-react';
import { Finding } from '../types.js';
import { SeverityBadge } from './SeverityBadge.js';

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onGeminiExplain?: (finding: Finding) => void;
  isExplaining?: boolean;
  geminiExplanation?: string | null;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({
  finding,
  onClose,
  onGeminiExplain,
  isExplaining,
  geminiExplanation,
}) => {
  return (
    <Drawer
      anchor="right"
      open={Boolean(finding)}
      onClose={onClose}
      sx={{
        '& .MuiDrawer-paper': {
          width: { xs: '100%', sm: 540 },
          bgcolor: '#09090b',
          borderLeft: '1px solid rgba(63, 63, 70, 0.5)',
          p: 3,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
          display: 'flex',
          flexDirection: 'column',
        },
      }}
    >
      {finding && (
        <>
          {/* Header */}
          <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', pb: 2, borderBottom: '1px solid rgba(63, 63, 70, 0.4)' }}>
            <Box sx={{ pr: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <SeverityBadge severity={finding.severity} />
                <Typography
                  variant="caption"
                  sx={{
                    fontFamily: '"JetBrains Mono", monospace',
                    color: '#a1a1aa',
                    fontWeight: 600,
                  }}
                >
                  {finding.findingId}
                </Typography>
                {finding.isDemo && (
                  <Chip
                    size="small"
                    label="DEMO"
                    sx={{
                      height: 18,
                      fontSize: '0.62rem',
                      fontFamily: '"JetBrains Mono", monospace',
                      bgcolor: 'rgba(245, 158, 11, 0.15)',
                      color: '#fbbf24',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                    }}
                  />
                )}
              </Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#f4f4f5', lineHeight: 1.3 }}>
                {finding.explanation}
              </Typography>
            </Box>
            <IconButton onClick={onClose} size="small" sx={{ color: '#a1a1aa', '&:hover': { color: '#ffffff', bgcolor: 'rgba(255,255,255,0.05)' } }}>
              <X size={20} />
            </IconButton>
          </Box>

          {/* Body Content */}
          <Box sx={{ mt: 3, flex: 1, overflowY: 'auto', pr: 0.5, display: 'flex', flexDirection: 'column', gap: 2.5 }}>
            {/* Metadata Grid */}
            <Paper
              elevation={0}
              sx={{
                p: 2,
                borderRadius: '8px',
                bgcolor: 'rgba(24, 24, 27, 0.6)',
                border: '1px solid rgba(63, 63, 70, 0.4)',
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: 1.5,
              }}
            >
              <Box>
                <Typography variant="caption" sx={{ color: '#71717a', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Category
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#e4e4e7', fontWeight: 600 }}>
                  {finding.category}
                </Typography>
              </Box>
              <Box>
                <Typography variant="caption" sx={{ color: '#71717a', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Assurance Confidence
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#34d399', fontWeight: 700 }}>
                  {(finding.confidence * 100).toFixed(1)}%
                </Typography>
              </Box>
              <Box sx={{ gridColumn: 'span 2' }}>
                <Typography variant="caption" sx={{ color: '#71717a', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Affected Asset
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: '"JetBrains Mono", monospace', color: '#cbd5e1', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                  {finding.affectedAsset}
                </Typography>
              </Box>
            </Paper>

            {/* Empirical Evidence */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <ShieldAlert size={16} color="#fbbf24" />
                <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#d4d4d8' }}>
                  Empirical Evidence
                </Typography>
              </Box>
              <Paper
                elevation={0}
                sx={{
                  p: 2,
                  borderRadius: '8px',
                  bgcolor: '#000000',
                  border: '1px solid rgba(63, 63, 70, 0.5)',
                  fontFamily: '"JetBrains Mono", monospace',
                  fontSize: '0.75rem',
                  color: '#e4e4e7',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-wrap',
                  maxHeight: 220,
                  overflowY: 'auto',
                }}
              >
                {typeof finding.evidence === 'string' ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}
              </Paper>
            </Box>

            {/* Recommendation */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Cpu size={16} color="#34d399" />
                <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#d4d4d8' }}>
                  Remediation Recommendation
                </Typography>
              </Box>
              <Paper
                elevation={0}
                sx={{
                  p: 2,
                  borderRadius: '8px',
                  bgcolor: 'rgba(6, 78, 59, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  color: '#a7f3d0',
                  fontSize: '0.82rem',
                  lineHeight: 1.5,
                }}
              >
                {finding.recommendation}
              </Paper>
            </Box>

            {/* Gemini AI Context */}
            <Box sx={{ pt: 1, borderTop: '1px solid rgba(63, 63, 70, 0.4)' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Sparkles size={16} color="#c084fc" />
                  <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#e9d5ff' }}>
                    Gemini AI Executive Briefing
                  </Typography>
                </Box>
                {onGeminiExplain && (
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => onGeminiExplain(finding)}
                    disabled={isExplaining}
                    startIcon={isExplaining ? <CircularProgress size={12} color="inherit" /> : <Sparkles size={13} />}
                    sx={{
                      fontSize: '0.72rem',
                      textTransform: 'none',
                      borderColor: 'rgba(168, 85, 247, 0.5)',
                      color: '#d8b4fe',
                      bgcolor: 'rgba(147, 51, 234, 0.1)',
                      '&:hover': {
                        borderColor: '#c084fc',
                        bgcolor: 'rgba(147, 51, 234, 0.2)',
                      },
                    }}
                  >
                    {isExplaining ? 'Analyzing...' : 'Analyze with Gemini'}
                  </Button>
                )}
              </Box>

              {geminiExplanation ? (
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    borderRadius: '8px',
                    bgcolor: 'rgba(88, 28, 135, 0.15)',
                    border: '1px solid rgba(168, 85, 247, 0.4)',
                    color: '#e9d5ff',
                    fontSize: '0.82rem',
                    lineHeight: 1.6,
                    whiteSpace: 'pre-line',
                  }}
                >
                  {geminiExplanation}
                </Paper>
              ) : (
                <Typography variant="caption" sx={{ color: '#71717a', fontStyle: 'italic', display: 'block' }}>
                  Optional Gemini explanation provides non-primary executive context for this deterministic finding.
                </Typography>
              )}
            </Box>
          </Box>

          {/* Footer */}
          <Box sx={{ pt: 2, borderTop: '1px solid rgba(63, 63, 70, 0.4)', display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              onClick={onClose}
              sx={{
                fontSize: '0.8rem',
                textTransform: 'none',
                borderColor: 'rgba(63, 63, 70, 0.8)',
                color: '#e4e4e7',
                '&:hover': {
                  borderColor: '#a1a1aa',
                  bgcolor: 'rgba(255, 255, 255, 0.05)',
                },
              }}
            >
              Close Inspector
            </Button>
          </Box>
        </>
      )}
    </Drawer>
  );
};
