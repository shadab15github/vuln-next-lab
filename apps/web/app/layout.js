import './globals.css';

export const metadata = {
  title: 'VulnLab — intentionally vulnerable Next.js monorepo',
  description: 'Security training / scanner benchmarking target. Do not deploy.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <main>
          <div className="banner">
            ⚠ INTENTIONALLY VULNERABLE APPLICATION — run only on localhost, in a
            throwaway environment. Never deploy or expose this to a network.
          </div>
          {children}
        </main>
      </body>
    </html>
  );
}
