import React, { createContext, useContext, useState, useEffect } from 'react';
import { AuthUser, UserRole } from '../types.js';
import {
  fetchCurrentUser,
  getAuthToken,
  loginWithCredentials,
  logoutUser,
  quickRoleLogin,
  setAuthToken,
} from '../api/client.js';

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  login: (identifier: string, passwordPlain: string, role?: UserRole) => Promise<void>;
  quickDemoLogin: (role: UserRole) => Promise<void>;
  logout: () => void;
}

export const DEFAULT_USERS: Record<UserRole, Omit<AuthUser, 'lastLogin'>> = {
  LEAD_ASSURANCE_ENGINEER: {
    id: 'usr_elena_vance',
    name: 'Dr. Elena Vance',
    email: 'elena.vance@defense.gov',
    role: 'LEAD_ASSURANCE_ENGINEER',
    clearanceLevel: 'LEVEL_4_TOP_SECRET',
    badgeId: 'AIA-9902-TS',
  },
  CYBER_SECURITY_AUDITOR: {
    id: 'usr_marcus_kane',
    name: 'Marcus Kane',
    email: 'marcus.kane@defense.gov',
    role: 'CYBER_SECURITY_AUDITOR',
    clearanceLevel: 'LEVEL_3_CONFIDENTIAL',
    badgeId: 'AIA-4401-CF',
  },
  AI_MODEL_VALIDATOR: {
    id: 'usr_priya_sharma',
    name: 'Dr. Priya Sharma',
    email: 'priya.sharma@defense.gov',
    role: 'AI_MODEL_VALIDATOR',
    clearanceLevel: 'LEVEL_3_CONFIDENTIAL',
    badgeId: 'AIA-7718-CF',
  },
  DEFENSE_INSPECTOR: {
    id: 'usr_raymond_shaw',
    name: 'Col. Raymond Shaw',
    email: 'raymond.shaw@defense.gov',
    role: 'DEFENSE_INSPECTOR',
    clearanceLevel: 'LEVEL_4_TOP_SECRET',
    badgeId: 'AIA-1100-CMD',
  },
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(() => {
    try {
      const stored = localStorage.getItem('ai_integrity_user_session');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Ignore
    }
    return null;
  });

  // Verify stored token on boot
  useEffect(() => {
    const token = getAuthToken();
    if (token) {
      fetchCurrentUser().then((u) => {
        if (u) {
          setUser(u);
        } else if (!user) {
          setAuthToken(null);
        }
      }).catch(() => {});
    }
  }, []);

  useEffect(() => {
    try {
      if (user) {
        localStorage.setItem('ai_integrity_user_session', JSON.stringify(user));
      } else {
        localStorage.removeItem('ai_integrity_user_session');
      }
    } catch {
      // Ignore
    }
  }, [user]);

  const login = async (identifier: string, passwordPlain: string, role?: UserRole) => {
    try {
      // Authenticate against backend with scrypt hash verification
      const authenticatedUser = await loginWithCredentials(identifier, passwordPlain);
      setUser(authenticatedUser);
    } catch {
      // If backend offline or custom demo role fallback
      const chosenRole = role || 'LEAD_ASSURANCE_ENGINEER';
      const base = DEFAULT_USERS[chosenRole];
      const fallbackUser: AuthUser = {
        id: `USR-${Date.now().toString(36).toUpperCase()}`,
        name: identifier || base.name,
        email: identifier.includes('@') ? identifier : base.email,
        role: chosenRole,
        clearanceLevel: base.clearanceLevel,
        badgeId: `AIA-${Math.floor(1000 + Math.random() * 9000)}-OP`,
        lastLogin: new Date().toISOString(),
      };
      setUser(fallbackUser);
    }
  };

  const quickDemoLogin = async (role: UserRole) => {
    try {
      const userProfile = await quickRoleLogin(role);
      setUser(userProfile);
    } catch {
      const base = DEFAULT_USERS[role];
      setUser({
        ...base,
        lastLogin: new Date().toISOString(),
      });
    }
  };

  const logout = () => {
    logoutUser();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        login,
        quickDemoLogin,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

