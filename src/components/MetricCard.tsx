import React from 'react';
import { Card, CardContent, Typography, Box } from '@mui/material';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  id?: string;
  label: string;
  value: string | number;
  subValue?: string;
  icon: LucideIcon;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

export const MetricCard: React.FC<MetricCardProps> = ({
  id,
  label,
  value,
  subValue,
  icon: Icon,
  variant = 'default',
}) => {
  const styles = {
    default: {
      border: '1px solid rgba(63, 63, 70, 0.5)',
      hoverBorder: 'rgba(113, 113, 122, 0.7)',
      bg: 'rgba(24, 24, 27, 0.7)',
      iconBg: 'rgba(39, 39, 42, 0.8)',
      iconColor: '#a1a1aa',
      valColor: '#f4f4f5',
    },
    danger: {
      border: '1px solid rgba(225, 29, 72, 0.4)',
      hoverBorder: 'rgba(225, 29, 72, 0.7)',
      bg: 'rgba(76, 5, 25, 0.2)',
      iconBg: 'rgba(159, 18, 57, 0.3)',
      iconColor: '#fb7185',
      valColor: '#f43f5e',
    },
    warning: {
      border: '1px solid rgba(217, 119, 6, 0.4)',
      hoverBorder: 'rgba(217, 119, 6, 0.7)',
      bg: 'rgba(69, 26, 3, 0.2)',
      iconBg: 'rgba(146, 64, 14, 0.3)',
      iconColor: '#fbbf24',
      valColor: '#f59e0b',
    },
    success: {
      border: '1px solid rgba(5, 150, 105, 0.4)',
      hoverBorder: 'rgba(5, 150, 105, 0.7)',
      bg: 'rgba(2, 44, 34, 0.2)',
      iconBg: 'rgba(6, 95, 70, 0.3)',
      iconColor: '#34d399',
      valColor: '#10b981',
    },
  }[variant];

  return (
    <Card
      id={id}
      elevation={0}
      sx={{
        border: styles.border,
        bgcolor: styles.bg,
        borderRadius: '12px',
        transition: 'all 0.2s ease-in-out',
        '&:hover': {
          borderColor: styles.hoverBorder,
          transform: 'translateY(-1px)',
        },
      }}
    >
      <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
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
            {label}
          </Typography>
          <Box
            sx={{
              p: 0.75,
              borderRadius: '8px',
              bgcolor: styles.iconBg,
              color: styles.iconColor,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Icon size={16} />
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
          <Typography
            variant="h4"
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontWeight: 800,
              color: styles.valColor,
              fontSize: '1.75rem',
              lineHeight: 1.1,
            }}
          >
            {value}
          </Typography>
          {subValue && (
            <Typography
              variant="caption"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                color: '#71717a',
                fontSize: '0.72rem',
              }}
            >
              {subValue}
            </Typography>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};
