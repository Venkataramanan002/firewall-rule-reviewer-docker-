import { NavLink, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Activity, ShieldAlert, BarChart3, Route, Wrench, Shield, User, LogOut, Network
} from "lucide-react";

const navItems = [
  { title: "Dashboard", path: "/", icon: LayoutDashboard },
  { title: "Live Traffic", path: "/live-traffic", icon: Activity },
  { title: "Threats", path: "/threats", icon: ShieldAlert },
  { title: "Analysis", path: "/analysis", icon: BarChart3 },
  { title: "Attack Paths", path: "/attack-paths", icon: Route },
  { title: "Remediation", path: "/remediation", icon: Wrench },
  { title: "FW Topology", path: "/firewall-topology", icon: Network },
];

export function AppSidebar() {
  const location = useLocation();

  return (
    <aside className="w-60 min-h-screen bg-card shadow-sidebar flex flex-col fixed left-0 top-0 z-40">
      {/* Logo */}
      <div className="h-14 flex items-center gap-2.5 px-5 border-b border-border">
        <Shield className="h-5 w-5 text-primary" />
        <span className="text-[13px] font-semibold tracking-tight text-foreground">
          Firewall Analytics
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={`flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] font-medium tracking-tight transition-smooth ${
                isActive
                  ? "sidebar-active"
                  : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
              }`}
            >
              <item.icon className="h-4 w-4" />
              <span>{item.title}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom section */}
      <div className="p-3 border-t border-border space-y-1">
        <div className="flex items-center gap-3 px-3 py-2 rounded-lg">
          <div className="h-7 w-7 rounded-full bg-primary/20 flex items-center justify-center">
            <User className="h-3.5 w-3.5 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[12px] font-medium text-foreground truncate">SOC Analyst</p>
            <p className="text-[10px] text-muted-foreground truncate">admin@firewall.local</p>
          </div>
          <LogOut className="h-3.5 w-3.5 text-muted-foreground cursor-pointer hover:text-foreground transition-smooth" />
        </div>
      </div>
    </aside>
  );
}
