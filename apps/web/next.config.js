/**
 * INTENTIONALLY INSECURE Next.js configuration.
 *
 *   V-CFG-01  CWE-942  Access-Control-Allow-Origin: * together with
 *                      Access-Control-Allow-Credentials: true
 *   V-CFG-02  CWE-1021 X-Frame-Options / frame-ancestors removed → clickjacking
 *   V-CFG-03  CWE-693  Content-Security-Policy set to a no-op
 *   V-CFG-04  CWE-200  x-powered-by kept, source maps shipped to production
 *   V-CFG-05  CWE-1188 Type and lint errors ignored during build
 *   V-CFG-06  CWE-16   images.remotePatterns opened to every host (SSRF surface
 *                      through the Next.js image optimizer)
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,

  transpilePackages: [
    '@vulnlab/ui',
    '@vulnlab/db',
    '@vulnlab/auth',
    '@vulnlab/utils',
    '@vulnlab/logger',
    '@vulnlab/api-client',
  ],

  // V-CFG-04 (CWE-200)
  poweredByHeader: true,
  productionBrowserSourceMaps: true,

  // V-CFG-05 (CWE-1188): ship regardless of what the checkers say.
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },

  // V-CFG-06 (CWE-16): the image optimizer will fetch from anywhere.
  images: {
    dangerouslyAllowSVG: true,
    contentDispositionType: 'inline',
    remotePatterns: [
      { protocol: 'https', hostname: '**' },
      { protocol: 'http', hostname: '**' },
    ],
  },

  // Not a planted flaw — alasql ships optional react-native requires that the
  // server bundle must not try to resolve.
  webpack: (config) => {
    config.resolve.fallback = {
      ...(config.resolve.fallback || {}),
      'react-native-fs': false,
      'react-native-fetch-blob': false,
    };
    return config;
  },

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          // V-CFG-01 (CWE-942): wildcard origin + credentials is the classic
          // misconfiguration that turns every authenticated endpoint into a
          // cross-origin read.
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,POST,PUT,PATCH,DELETE,OPTIONS' },
          { key: 'Access-Control-Allow-Headers', value: '*' },

          // V-CFG-02 (CWE-1021) / V-CFG-03 (CWE-693)
          { key: 'X-Frame-Options', value: 'ALLOWALL' },
          { key: 'Content-Security-Policy', value: "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:" },
          { key: 'Referrer-Policy', value: 'unsafe-url' },
          { key: 'X-Content-Type-Options', value: 'nosniff-disabled' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
