import type { Metadata } from 'next';
import Script from 'next/script';
import { cookies } from 'next/headers';
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import { ThemeProvider, type Theme } from '@/components/theme-provider';
import { THEME_COOKIE, getThemeCookie } from '@/lib/auth/session';
import './globals.scss';

const plexSans = IBM_Plex_Sans({
  weight: ['300', '400', '600'],
  subsets: ['latin'],
  variable: '--font-plex-sans',
  display: 'swap',
});

const plexMono = IBM_Plex_Mono({
  weight: ['400', '600'],
  subsets: ['latin'],
  variable: '--font-plex-mono',
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'AI Runtime Security',
  description: 'Governed conversations for your AI runtime, powered by Keycloak, Vault and LiteLLM.',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const cookieStore = await cookies();
  const theme: Theme = getThemeCookie(cookieStore.get(THEME_COOKIE)?.value);
  const siteKey = process.env.NEXT_PUBLIC_SITE_KEY || '';
  const siteBackend = process.env.NEXT_PUBLIC_SITE_BACKEND || '';
  const siteAgentVersion = process.env.NEXT_PUBLIC_SITE_AGENT_VERSION || '';
  const siteAgentIntegrity = process.env.NEXT_PUBLIC_SITE_AGENT_INTEGRITY || '';

  return (
    <html
      lang="en"
      data-carbon-theme={theme}
      className={`${plexSans.variable} ${plexMono.variable}`}
      suppressHydrationWarning
    >
      <body
        style={{
          fontFamily: `var(--font-plex-sans), 'IBM Plex Sans', 'Helvetica Neue', Arial, sans-serif`,
        }}
      >
        <Script id="instana-eum-init" strategy="afterInteractive">{`
          (function (s, t, a, n) {
            s[t] || (s[t] = a, n = s[a] = function () { n.q.push(arguments); },
              n.q = [], n.v = 2, n.l = 1 * new Date());
          })(window, 'InstanaEumObject', 'ineum');

          ineum('reportingUrl', '${siteBackend}');
          ineum('key', '${siteKey}');
          ineum('trackSessions');
          ineum('enableW3CHeaders', true);
          ineum('autoPageDetection', true);
          ineum('meta', 'environment', 'demo');
        `}</Script>
        <Script
          defer
          crossOrigin="anonymous"
          src={`https://eum.instana.io/${siteAgentVersion}/eum.min.js`}
          integrity={siteAgentIntegrity}
        />
        <ThemeProvider initialTheme={theme}>{children}</ThemeProvider>
      </body>
    </html>
  );
}
