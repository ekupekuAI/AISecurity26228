/**
 * Session state.
 *
 * The previous implementation auto-authenticated as a Level-4 engineer on mount and, if
 * the backend refused, fabricated a client-side user object so the console carried on
 * regardless. That is not authentication; it is a login screen that never appears.
 *
 * Here the console starts signed out, the server is the only source of identity, and a
 * failed session check returns the user to the sign-in screen rather than inventing one.
 */

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { AuthUser } from '../types.js';
import {
  ApiError,
  changePassword as apiChangePassword,
  fetchCurrentUser,
  login as apiLogin,
  loginAsObserver as apiLoginAsObserver,
  logout as apiLogout,
  setUnauthenticatedHandler,
} from '../api/client.js';

interface AuthState {
  user: AuthUser | null;
  status: 'checking' | 'anonymous' | 'authenticated';
  demoMode: boolean;
  expiresAt: string | null;
  notice: string | null;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  isAuthenticated: boolean;
  can: (capability: string) => boolean;
  login: (identifier: string, password: string) => Promise<void>;
  loginAsObserver: () => Promise<void>;
  logout: () => Promise<void>;
  changePassword: (current: string, next: string) => Promise<string>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [state, setState] = useState<AuthState>({
    user: null,
    status: 'checking',
    demoMode: false,
    expiresAt: null,
    notice: null,
    error: null,
  });

  const signOutLocally = useCallback(() => {
    setState((previous) => ({
      ...previous,
      user: null,
      status: 'anonymous',
      expiresAt: null,
      notice: null,
    }));
  }, []);

  // Any 401 from anywhere in the app returns the console to the sign-in screen, so an
  // expired or revoked session cannot leave a half-live UI showing stale evidence.
  useEffect(() => {
    setUnauthenticatedHandler(signOutLocally);
    return () => setUnauthenticatedHandler(null);
  }, [signOutLocally]);

  useEffect(() => {
    let cancelled = false;
    fetchCurrentUser()
      .then((session) => {
        if (cancelled) return;
        if (session) {
          setState({
            user: session.user,
            status: 'authenticated',
            demoMode: session.demoMode,
            expiresAt: session.expiresAt,
            notice: null,
            error: null,
          });
        } else {
          setState((previous) => ({ ...previous, status: 'anonymous' }));
        }
      })
      .catch(() => {
        if (!cancelled) setState((previous) => ({ ...previous, status: 'anonymous' }));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (identifier: string, password: string) => {
    setState((previous) => ({ ...previous, error: null }));
    try {
      const result = await apiLogin(identifier, password);
      setState((previous) => ({
        ...previous,
        user: result.user,
        status: 'authenticated',
        expiresAt: result.expiresAt,
        notice: null,
        error: null,
      }));
    } catch (error) {
      const message =
        error instanceof ApiError
          ? error.code === 'ACCOUNT_LOCKED'
            ? 'Too many failed attempts. This account is temporarily locked.'
            : error.code === 'RATE_LIMITED'
            ? 'Too many sign-in attempts from this address. Wait a minute and try again.'
            : error.message
          : 'Sign-in failed.';
      setState((previous) => ({ ...previous, error: message, status: 'anonymous' }));
      throw error;
    }
  }, []);

  const loginAsObserver = useCallback(async () => {
    setState((previous) => ({ ...previous, error: null }));
    try {
      const result = await apiLoginAsObserver();
      setState((previous) => ({
        ...previous,
        user: result.user,
        status: 'authenticated',
        expiresAt: result.expiresAt,
        notice: result.notice ?? null,
        error: null,
      }));
    } catch (error) {
      const message =
        error instanceof ApiError && error.code === 'DEMO_DISABLED'
          ? 'Evaluation sessions are disabled on this node.'
          : 'Could not start an evaluation session.';
      setState((previous) => ({ ...previous, error: message }));
      throw error;
    }
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    signOutLocally();
  }, [signOutLocally]);

  const changePassword = useCallback(async (current: string, next: string) => {
    const result = await apiChangePassword(current, next);
    // The server invalidates every session on a password change, so the console must
    // return to the sign-in screen rather than continuing with a dead cookie.
    signOutLocally();
    return result.message;
  }, [signOutLocally]);

  const can = useCallback(
    (capability: string) => Boolean(state.user?.capabilities?.includes(capability)),
    [state.user]
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      isAuthenticated: state.status === 'authenticated' && state.user !== null,
      can,
      login,
      loginAsObserver,
      logout,
      changePassword,
      clearError: () => setState((previous) => ({ ...previous, error: null })),
    }),
    [state, can, login, loginAsObserver, logout, changePassword]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
