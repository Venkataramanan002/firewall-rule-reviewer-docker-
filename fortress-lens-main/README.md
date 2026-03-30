# Firewall Rule Reviewer - Frontend (Fortress Lens)

This directory contains the React + Vite frontend for the **Firewall Rule Reviewer** application. 
It provides a production-grade UI to analyze firewall configurations, visualize topologies, evaluate risks, and simulate network attack paths.

## 🚀 Quick Start (Development)

To run the frontend separately from the backend during development:

```sh
# Install dependencies
npm install

# Start the development server
npm run dev
```

The frontend will start at **http://localhost:8080**.

> **Note**: For the UI to show real data, the FastAPI backend must be running on `http://localhost:8000`. In development, requests to `/api` are automatically proxied there.

## 📦 Building for Production

To create a production-ready build:

```sh
npm run build
```

This commands bundles the React application into the `dist/` directory using Vite. These static files can then be served by:
- The FastAPI backend (already configured to serve static files).
- Nginx or another web server.
- Supported hosting platforms like Vercel or Netlify.

## ✨ Tech Stack

- **Framework**: React.js with TypeScript
- **Bundler**: Vite
- **Routing**: React Router
- **Styling**: Tailwind CSS
- **Data Visualization**: Recharts, React Flow
- **State/Querying**: React Query (TanStack Query)

## 📁 Architecture
- `src/pages`: Main application views (Dashboard, LiveTraffic, Threats, Analysis, AttackPaths, Remediation).
- `src/components`: Reusable UI components.
- `src/lib/api.ts`: **Single source of truth** for backend communication. Every frontend piece interacts with real data. **No mock data is used**. 
- `public/`: Static assets (images, icons, etc.).

For more information about the entire architecture (including the backend), please see the main [README.md](../README.md) in the project root.
