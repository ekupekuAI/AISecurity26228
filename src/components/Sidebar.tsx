import React from 'react';
import {
  Drawer,
  Box,
  Typography,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Chip,
  Divider,
} from '@mui/material';
import {
  ShieldAlert,
  Database,
  Cpu,
  Fingerprint,
  TrendingUp,
  History,
  Settings,
  BookOpen,
  Activity,
  LineChart,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
} from 'lucide-react';
import { NavTab } from './Navigation.js';

export const SIDEBAR_WIDTH = 270;

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  mlStatus: 'ONLINE' | 'OFFLINE' | 'CHECKING';
  overallTrustScore: number;
  mobileOpen: boolean;
  onMobileClose: () => void;
}

interface NavGroup {
  title: string;
  items: {
    id: NavTab;
    label: string;
    icon: React.ComponentType<{ size?: number; className?: string; color?: string }>;
    badge?: string;
  }[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onTabChange,
  mlStatus,
  overallTrustScore,
  mobileOpen,
  onMobileClose,
}) => {
  const navGroups: NavGroup[] = [
    {
      title: 'PLATFORM COMMAND',
      items: [
        { id: 'dashboard', label: 'Mission Command', icon: Activity },
        { id: 'evaluation', label: 'Prediction Graphs', icon: LineChart, badge: 'Charts' },
      ],
    },
    {
      title: 'PIPELINE ASSURANCE',
      items: [
        { id: 'dataset', label: 'Dataset Forensics', icon: Database },
        { id: 'model', label: 'Model Integrity', icon: Cpu },
        { id: 'inference', label: 'Inference Provenance', icon: Fingerprint },
        { id: 'shift', label: 'Distribution Shift', icon: TrendingUp },
      ],
    },
    {
      title: 'AUDIT & GOVERNANCE',
      items: [
        { id: 'history', label: 'Audit Ledger & Certs', icon: History },
      ],
    },
    {
      title: 'SYSTEM & SPEC',
      items: [
        { id: 'config', label: 'System Config', icon: Settings },
        { id: 'methodology', label: 'Methodology & Spec', icon: BookOpen },
      ],
    },
  ];

  const sidebarContent = (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        bgcolor: '#09090b',
        borderRight: '1px solid rgba(63, 63, 70, 0.4)',
      }}
    >
      {/* Sidebar Header / Brand */}
      <Box
        onClick={() => {
          onTabChange('dashboard');
          onMobileClose();
        }}
        sx={{
          p: 2.5,
          cursor: 'pointer',
          borderBottom: '1px solid rgba(63, 63, 70, 0.35)',
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          bgcolor: 'rgba(16, 185, 129, 0.03)',
          transition: 'background-color 0.2s',
          '&:hover': {
            bgcolor: 'rgba(16, 185, 129, 0.06)',
          },
        }}
      >
        <Box
          sx={{
            width: 40,
            height: 40,
            borderRadius: '10px',
            bgcolor: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            color: '#10b981',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 15px rgba(16, 185, 129, 0.2)',
          }}
        >
          <ShieldAlert size={22} />
        </Box>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography
              variant="subtitle2"
              sx={{
                fontWeight: 800,
                color: '#f4f4f5',
                letterSpacing: '-0.01em',
                lineHeight: 1.2,
                fontSize: '0.9rem',
              }}
            >
              AI INTEGRITY
            </Typography>
            <Chip
              label="SIH26228"
              size="small"
              sx={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: '0.62rem',
                fontWeight: 700,
                height: 18,
                bgcolor: 'rgba(16, 185, 129, 0.15)',
                color: '#34d399',
                border: '1px solid rgba(16, 185, 129, 0.4)',
              }}
            />
          </Box>
          <Typography
            variant="caption"
            sx={{
              color: '#a1a1aa',
              fontSize: '0.68rem',
              display: 'block',
              fontFamily: '"JetBrains Mono", monospace',
              mt: 0.25,
            }}
          >
            Assurance &amp; Forensics
          </Typography>
        </Box>
      </Box>

      {/* Trust & Engine Mini-Card */}
      <Box
        sx={{
          mx: 2,
          mt: 2,
          p: 1.5,
          borderRadius: '8px',
          bgcolor: 'rgba(24, 24, 27, 0.6)',
          border: '1px solid rgba(63, 63, 70, 0.4)',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.75 }}>
          <Typography
            variant="caption"
            sx={{
              color: '#a1a1aa',
              fontSize: '0.65rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              display: 'flex',
              alignItems: 'center',
              gap: 0.75,
            }}
          >
            <ShieldCheck size={12} color="#10b981" /> Trust Index
          </Typography>
          <Typography
            variant="caption"
            sx={{
              fontFamily: '"JetBrains Mono", monospace',
              fontWeight: 800,
              fontSize: '0.8rem',
              color:
                overallTrustScore >= 80 ? '#34d399' : overallTrustScore >= 60 ? '#fbbf24' : '#f87171',
            }}
          >
            {overallTrustScore}/100
          </Typography>
        </Box>
        <Box
          sx={{
            height: 4,
            width: '100%',
            borderRadius: '2px',
            bgcolor: 'rgba(63, 63, 70, 0.4)',
            overflow: 'hidden',
          }}
        >
          <Box
            sx={{
              height: '100%',
              width: `${overallTrustScore}%`,
              bgcolor:
                overallTrustScore >= 80 ? '#10b981' : overallTrustScore >= 60 ? '#f59e0b' : '#ef4444',
              transition: 'width 0.5s ease',
            }}
          />
        </Box>
      </Box>

      {/* Navigation Links (Scrollable) */}
      <Box sx={{ flex: 1, overflowY: 'auto', py: 1.5, px: 1.5 }}>
        {navGroups.map((group, groupIdx) => (
          <Box key={group.title} sx={{ mb: groupIdx === navGroups.length - 1 ? 0 : 2 }}>
            <Typography
              variant="caption"
              sx={{
                px: 1.5,
                py: 0.5,
                display: 'block',
                fontSize: '0.62rem',
                fontWeight: 700,
                color: '#71717a',
                letterSpacing: '0.08em',
                fontFamily: '"JetBrains Mono", monospace',
              }}
            >
              {group.title}
            </Typography>
            <List dense sx={{ p: 0, mt: 0.5 }}>
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.id;
                return (
                  <ListItem key={item.id} disablePadding sx={{ mb: 0.5 }}>
                    <ListItemButton
                      onClick={() => {
                        onTabChange(item.id);
                        onMobileClose();
                      }}
                      sx={{
                        borderRadius: '8px',
                        py: 0.85,
                        px: 1.5,
                        transition: 'all 0.15s ease',
                        bgcolor: isActive ? 'rgba(16, 185, 129, 0.12)' : 'transparent',
                        border: isActive
                          ? '1px solid rgba(16, 185, 129, 0.35)'
                          : '1px solid transparent',
                        color: isActive ? '#f4f4f5' : '#a1a1aa',
                        '&:hover': {
                          bgcolor: isActive
                            ? 'rgba(16, 185, 129, 0.18)'
                            : 'rgba(255, 255, 255, 0.04)',
                          color: '#ffffff',
                          transform: 'translateX(2px)',
                        },
                      }}
                    >
                      <ListItemIcon
                        sx={{
                          minWidth: 32,
                          color: isActive ? '#10b981' : '#71717a',
                        }}
                      >
                        <Icon size={18} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography
                            sx={{
                              fontSize: '0.8rem',
                              fontWeight: isActive ? 700 : 500,
                              color: 'inherit',
                              lineHeight: 1.3,
                            }}
                          >
                            {item.label}
                          </Typography>
                        }
                      />
                      {isActive && (
                        <Box
                          sx={{
                            width: 6,
                            height: 6,
                            borderRadius: '50%',
                            bgcolor: '#10b981',
                            boxShadow: '0 0 6px #10b981',
                          }}
                        />
                      )}
                    </ListItemButton>
                  </ListItem>
                );
              })}
            </List>
          </Box>
        ))}
      </Box>

      {/* Engine Status Line */}
      <Box
        sx={{
          px: 2,
          py: 1.25,
          borderTop: '1px solid rgba(63, 63, 70, 0.3)',
          bgcolor: 'rgba(18, 18, 20, 0.6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Typography variant="caption" sx={{ color: '#71717a', fontSize: '0.68rem', fontFamily: 'monospace' }}>
          ML Engine
        </Typography>
        {mlStatus === 'ONLINE' ? (
          <Chip
            size="small"
            icon={<CheckCircle2 size={12} color="#10b981" />}
            label="FastAPI Python"
            sx={{
              height: 22,
              fontSize: '0.65rem',
              fontWeight: 600,
              bgcolor: 'rgba(16, 185, 129, 0.12)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              '& .MuiChip-icon': { ml: 0.75 },
            }}
          />
        ) : mlStatus === 'CHECKING' ? (
          <Chip
            size="small"
            label="Connecting..."
            sx={{ height: 22, fontSize: '0.65rem', bgcolor: 'rgba(63,63,70,0.3)', color: '#a1a1aa' }}
          />
        ) : (
          <Chip
            size="small"
            icon={<AlertTriangle size={12} color="#f59e0b" />}
            label="Standalone Node"
            sx={{
              height: 22,
              fontSize: '0.65rem',
              fontWeight: 600,
              bgcolor: 'rgba(245, 158, 11, 0.12)',
              color: '#fbbf24',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              '& .MuiChip-icon': { ml: 0.75 },
            }}
          />
        )}
      </Box>

      {/* Platform Assurance Footer */}
      <Box
        sx={{
          p: 1.5,
          borderTop: '1px solid rgba(63, 63, 70, 0.4)',
          bgcolor: 'rgba(18, 18, 20, 0.95)',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
          <Box
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              bgcolor: '#10b981',
              boxShadow: '0 0 8px #10b981',
            }}
          />
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography
              variant="body2"
              noWrap
              sx={{ fontWeight: 700, fontSize: '0.75rem', color: '#f4f4f5' }}
            >
              Defense Assurance Active
            </Typography>
            <Typography
              variant="caption"
              noWrap
              sx={{
                color: '#71717a',
                fontSize: '0.65rem',
                display: 'block',
                fontFamily: '"JetBrains Mono", monospace',
              }}
            >
              FIPS 180-4 SHA-256 Ledger
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );

  return (
    <>
      {/* Mobile Temporary Drawer */}
      <Drawer
        variant="temporary"
        open={mobileOpen}
        onClose={onMobileClose}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: 'block', md: 'none' },
          '& .MuiDrawer-paper': {
            boxSizing: 'border-box',
            width: SIDEBAR_WIDTH,
            border: 'none',
          },
        }}
      >
        {sidebarContent}
      </Drawer>

      {/* Desktop Permanent Drawer */}
      <Drawer
        variant="permanent"
        sx={{
          display: { xs: 'none', md: 'block' },
          width: SIDEBAR_WIDTH,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: SIDEBAR_WIDTH,
            boxSizing: 'border-box',
            border: 'none',
          },
        }}
        open
      >
        {sidebarContent}
      </Drawer>
    </>
  );
};
