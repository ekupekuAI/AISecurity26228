import React from 'react';
import { Chip } from '@mui/material';
import { FindingSeverity } from '../types.js';

interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const normalized = (severity || 'INFO').toUpperCase();

  let bg = 'rgba(39, 39, 42, 0.6)';
  let border = 'rgba(63, 63, 70, 0.8)';
  let textColor = '#d4d4d8';

  if (normalized === 'CRITICAL') {
    bg = 'rgba(239, 68, 68, 0.18)';
    border = 'rgba(239, 68, 68, 0.6)';
    textColor = '#fca5a5';
  } else if (normalized === 'HIGH') {
    bg = 'rgba(249, 115, 22, 0.18)';
    border = 'rgba(249, 115, 22, 0.6)';
    textColor = '#fdba74';
  } else if (normalized === 'MEDIUM') {
    bg = 'rgba(245, 158, 11, 0.18)';
    border = 'rgba(245, 158, 11, 0.6)';
    textColor = '#fcd34d';
  } else if (normalized === 'LOW') {
    bg = 'rgba(59, 130, 246, 0.18)';
    border = 'rgba(59, 130, 246, 0.6)';
    textColor = '#93c5fd';
  } else if (normalized === 'INFO') {
    bg = 'rgba(39, 39, 42, 0.6)';
    border = 'rgba(63, 63, 70, 0.8)';
    textColor = '#d4d4d8';
  }

  const height = size === 'sm' ? 20 : 24;
  const fontSize = size === 'sm' ? '0.62rem' : '0.7rem';

  return (
    <Chip
      size="small"
      label={normalized}
      sx={{
        height,
        fontSize,
        fontWeight: 700,
        fontFamily: '"JetBrains Mono", monospace',
        letterSpacing: '0.05em',
        bgcolor: bg,
        color: textColor,
        border: `1px solid ${border}`,
        borderRadius: '4px',
        '& .MuiChip-label': {
          px: 1,
        },
      }}
    />
  );
};
