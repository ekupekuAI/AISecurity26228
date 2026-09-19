/**
 * Workbench state that outlives the page it was started from.
 *
 * The inspection pages mount and unmount as the operator moves between tabs. If each page
 * held its own upload/result in local state, switching away and back would wipe a chosen
 * file or a finished assessment — and a long analysis begun on one tab would be cancelled
 * the moment the operator looked at another. This provider sits above the tab switch, so:
 *
 *  - a dataset and a model analysis run independently and concurrently;
 *  - each keeps its selected file, its in-flight state and its result across navigation;
 *  - an analysis started on one tab continues in the background and toasts when it lands,
 *    so the operator never has to sit and watch a spinner.
 */

import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { DatasetAnalysisResult, ModelAnalysisResult } from '../types.js';
import { analyzeDataset, analyzeModel } from '../api/client.js';

type ToastFn = (tone: 'ok' | 'error' | 'info', title: string, detail?: string) => void;

export interface AnalysisSlot<T> {
  result: T | null;
  busy: boolean;
  fileName: string | null;
  error: string | null;
}

const EMPTY: AnalysisSlot<never> = { result: null, busy: false, fileName: null, error: null };

interface WorkbenchValue {
  dataset: AnalysisSlot<DatasetAnalysisResult>;
  model: AnalysisSlot<ModelAnalysisResult>;
  runDataset: (file: File) => void;
  runModel: (file: File) => void;
  resetDataset: () => void;
  resetModel: () => void;
}

const WorkbenchContext = createContext<WorkbenchValue | null>(null);

export function WorkbenchProvider({
  children,
  pushToast,
  onComplete,
}: {
  children: React.ReactNode;
  pushToast: ToastFn;
  onComplete: () => void | Promise<void>;
}) {
  const [dataset, setDataset] = useState<AnalysisSlot<DatasetAnalysisResult>>(EMPTY);
  const [model, setModel] = useState<AnalysisSlot<ModelAnalysisResult>>(EMPTY);

  const runDataset = useCallback(
    (file: File) => {
      setDataset({ result: null, busy: true, fileName: file.name, error: null });
      // No AbortSignal is passed: the request must survive this page unmounting.
      analyzeDataset(file)
        .then((analysis) => {
          setDataset({ result: analysis, busy: false, fileName: file.name, error: null });
          pushToast(
            analysis.status === 'DETECTED' ? 'error' : 'ok',
            `Dataset · ${analysis.status} · risk ${analysis.datasetRisk}/100`,
            `${analysis.totalSamples} samples in ${analysis.analysisDurationSeconds?.toFixed(1) ?? '?'}s`
          );
          void onComplete();
        })
        .catch((error: unknown) => {
          const message = error instanceof Error ? error.message : 'Analysis failed';
          setDataset({ result: null, busy: false, fileName: file.name, error: message });
          pushToast('error', 'Dataset analysis failed', message);
        });
    },
    [pushToast, onComplete]
  );

  const runModel = useCallback(
    (file: File) => {
      setModel({ result: null, busy: true, fileName: file.name, error: null });
      analyzeModel(file)
        .then((analysis) => {
          setModel({ result: analysis, busy: false, fileName: file.name, error: null });
          pushToast(
            analysis.status === 'DETECTED' ? 'error' : 'ok',
            `Model · ${analysis.status} · risk ${analysis.modelRisk}/100`,
            `${analysis.analysisMode} access · ${analysis.analysisDurationSeconds?.toFixed(1) ?? '?'}s`
          );
          void onComplete();
        })
        .catch((error: unknown) => {
          const message = error instanceof Error ? error.message : 'Analysis failed';
          setModel({ result: null, busy: false, fileName: file.name, error: message });
          pushToast('error', 'Model analysis failed', message);
        });
    },
    [pushToast, onComplete]
  );

  const resetDataset = useCallback(() => setDataset(EMPTY), []);
  const resetModel = useCallback(() => setModel(EMPTY), []);

  const value = useMemo<WorkbenchValue>(
    () => ({ dataset, model, runDataset, runModel, resetDataset, resetModel }),
    [dataset, model, runDataset, runModel, resetDataset, resetModel]
  );

  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

export function useWorkbench(): WorkbenchValue {
  const value = useContext(WorkbenchContext);
  if (!value) throw new Error('useWorkbench must be used within a WorkbenchProvider');
  return value;
}
