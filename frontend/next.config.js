/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  output: 'export',
  trailingSlash: true,
  basePath: '/CVE',
  assetPrefix: '/CVE/',
  images: {
    unoptimized: true,
  },
  // When output is 'export', trailingSlash + basePath must align with the hosting path
  // On GitHub Pages the site lives at /CVE/
}

module.exports = nextConfig
