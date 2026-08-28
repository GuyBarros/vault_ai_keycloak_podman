'use client';

import { useEffect } from 'react';

declare global {
  interface Window {
    ineum?: (...args: unknown[]) => void;
  }
}

export function InstanaUserTracker({ user }: { user?: string | null }) {
  useEffect(() => {
    if (typeof window === 'undefined' || !window.ineum) return;

    if (user) {
      // Set user context in Instana
      window.ineum('user', null, null, user);
    } else {
      // Clear user context on logout / unauthenticated states
      window.ineum('user');
    }
  }, [user]); // Granular dependency array

  return null;
}