import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const isProd = process.env.NODE_ENV === 'production';

const scriptSrc = isProd
  ? "script-src 'self' 'unsafe-inline' https://eum.instana.io"
  : "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://eum.instana.io";

const connectSrc = isProd
  ? "connect-src 'self' https://eum-orange-saas.instana.io"
  : "connect-src 'self' 'unsafe-eval' https://eum-orange-saas.instana.io";

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=()',
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      scriptSrc,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      connectSrc,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; '),
  },
];

if (isProd) {
  securityHeaders.push({
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  });
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  outputFileTracingRoot: __dirname,
  reactStrictMode: true,
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  serverExternalPackages: [
    '@opentelemetry/instrumentation',
    '@opentelemetry/instrumentation-pino',
    '@opentelemetry/sdk-node',
    '@opentelemetry/sdk-trace-node',
    'pino',
  ],
  sassOptions: {
    includePaths: [path.join(__dirname, 'src')],
    silenceDeprecations: ['mixed-decls', 'legacy-js-api', 'import'],
  },
  transpilePackages: ['@carbon/react', '@carbon/icons-react'],
  async headers() {
    const baseRule = { source: '/:path*', headers: securityHeaders };
    if (isProd) return [baseRule];
    return [
      baseRule,
      {
        source: '/:path*',
        headers: [
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, proxy-revalidate' },
          { key: 'Pragma', value: 'no-cache' },
          { key: 'Expires', value: '0' },
        ],
      },
    ];
  },
};

export default nextConfig;
