/** Props every page receives from the console shell. */
import type { Finding } from '../../types.js';

export interface PageProps {
  onFindingClick: (finding: Finding) => void;
  onRefresh: () => void | Promise<void>;
  pushToast: (tone: 'ok' | 'error' | 'info', title: string, detail?: string) => void;
}
