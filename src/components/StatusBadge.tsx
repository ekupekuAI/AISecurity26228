import React from 'react';
import { Chip, Box } from '@mui/material';
import { AssuranceStatus } from '../types.js';

interface StatusBadgeProps {
  status: AssuranceStatus | 'VERIFIED' | 'TAMPERED' | string;
  size?: 'sm' | 'md' | 'lg';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const normalized = (status || '').toUpperCase();

  let color: 'default' | 'error' | 'warning' | 'success' | 'info' | 'secondary' = 'default';
  let dotColor = '#71717a';
  let bg = 'rgba(39, 39, 42, 0.6)';
  let border = 'rgba(63, 63, 70, 0.8)';
  let textColor = '#d4d4d8';

  if (normalized === 'DETECTED' || normalized === 'TAMPERED') {
    color = 'error';
    dotColor = '#f43f5e';
    bg = 'rgba(244, 63, 94, 0.12)';
    border = 'rgba(244, 63, 94, 0.4)';
    textColor = '#fca5a5';
  } else if (normalized === 'SUSPICIOUS' || normalized === 'WARNING') {
    color = 'warning';
    dotColor = '#f59e0b';
    bg = 'rgba(245, 158, 11, 0.12)';
    border = 'rgba(245, 158, 11, 0.4)';
    textColor = '#fcd34d';
  } else if (normalized === 'NOT DETECTED' || normalized === 'VERIFIED') {
    color = 'success';
    dotColor = '#10b981';
    bg = 'rgba(16, 185, 129, 0.12)';
    border = 'rgba(16, 185, 129, 0.4)';
    textColor = '#6ee7b7';
  } else if (normalized === 'NOT SUPPORTED') {
    color = 'info';
    dotColor = '#06b6d4';
    bg = 'rgba(6, 182, 212, 0.12)';
    border = 'rgba(6, 182, 212, 0.4)';
    textColor = '#67e8f9';
  } else if (normalized === 'ANALYSIS FAILED') {
    color = 'secondary';
    dotColor = '#a855f7';
    bg = 'rgba(168, 85, 247, 0.12)';
    border = 'rgba(168, 85, 247, 0.4)';
    textColor = '#d8b4fe';
  }

  const height = size === 'sm' ? 22 : size === 'lg' ? 32 : 26;
  const fontSize = size === 'sm' ? '0.65rem' : size === 'lg' ? '0.8rem' : '0.72rem';

  return (
    <Chip
      size="small"
      icon={
        <Box
          component="span"
          sx={{
            width: 6,
            height: 6,
            borderRadius: '50%',
            bgcolor: dotColor,
            ml: 1,
            mr: -0.5,
            boxShadow: `0 0 6px ${dotColor}`,
          }}
        />
      }
      label={normalized}
      sx={{
        height,
        fontSize,
        fontWeight: 700,
        fontFamily: '"JetBrains Mono", monospace',
        letterSpacing: '0.04em',
        bgcolor: bg,
        color: textColor,
        border: `1px solid ${border}`,
        borderRadius: '6px',
        '& .MuiChip-label': {
          px: 1,
        },
      }}
    />
  );
};
