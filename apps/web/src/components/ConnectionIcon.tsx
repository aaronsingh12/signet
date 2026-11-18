import type { ReactNode } from 'react';

export function ConnectionIcon({ children, tone }: { children: ReactNode; tone: 'ok' | 'warn' | 'bad' }) {
  return <span aria-hidden="true" className={`connection-icon connection-icon-${tone}`}>{children}</span>;
}
