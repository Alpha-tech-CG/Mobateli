// Public marketing site (edited in Framer) served under this app's domain.
// When MARKETING_SITE_URL is set, "/" and any path the app doesn't handle are
// proxied to it; app routes (/login, /dashboard, …) always win.
const marketing = process.env.MARKETING_SITE_URL?.replace(/\/+$/, "");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    if (!marketing) return [];
    return {
      beforeFiles: [{ source: "/", destination: `${marketing}/` }],
      afterFiles: [],
      fallback: [{ source: "/:path*", destination: `${marketing}/:path*` }],
    };
  },
};

export default nextConfig;
