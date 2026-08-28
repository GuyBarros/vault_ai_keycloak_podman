'use client';

import { useTheme, type Theme } from '@/components/theme-provider';

export function ThemeSelect() {
  const { theme, setTheme } = useTheme();
  return (
    <div className="app-header__select">
      <select
        value={theme}
        onChange={(e) => setTheme(e.target.value as Theme)}
        aria-label="Theme"
      >
        <option value="white">White</option>
        <option value="g100">Dark</option>
      </select>
    </div>
  );
}
