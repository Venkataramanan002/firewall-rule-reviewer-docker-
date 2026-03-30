import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Index from "./pages/Index.tsx";
import LiveTraffic from "./pages/LiveTraffic.tsx";
import Threats from "./pages/Threats.tsx";
import Analysis from "./pages/Analysis.tsx";
import AttackPaths from "./pages/AttackPaths.tsx";
import Remediation from "./pages/Remediation.tsx";
import FirewallTopology from "./pages/FirewallTopology.tsx";
import NotFound from "./pages/NotFound.tsx";

const queryClient = new QueryClient();

class AppErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground p-8">
          <div className="max-w-lg space-y-3">
            <p className="text-destructive font-semibold text-sm">Something went wrong rendering this page.</p>
            <pre className="text-[11px] text-muted-foreground whitespace-pre-wrap bg-card rounded-lg p-4 border border-border">
              {(this.state.error as Error).message}
            </pre>
            <button
              onClick={() => this.setState({ error: null })}
              className="text-xs text-primary underline"
            >
              Try again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const App = () => (
  <AppErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={300}>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/live-traffic" element={<LiveTraffic />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/analysis" element={<Analysis />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/remediation" element={<Remediation />} />
            <Route path="/firewall-topology" element={<FirewallTopology />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </AppErrorBoundary>
);

export default App;
