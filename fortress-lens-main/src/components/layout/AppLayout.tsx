import { ReactNode } from "react";
import { AppSidebar } from "./AppSidebar";

interface AppLayoutProps {
  children: ReactNode;
  title: string;
  breadcrumb?: string[];
}

export function AppLayout({ children, title, breadcrumb = [] }: AppLayoutProps) {
  return (
    <div className="min-h-screen flex w-full">
      <AppSidebar />
      <div className="flex-1 flex flex-col ml-60">
        {/* Header */}
        <header className="h-14 flex items-center px-6 bg-background/80 backdrop-blur-md sticky top-0 z-30 border-b border-border">
          <div className="flex items-center gap-2 text-[13px]">
            {breadcrumb.map((crumb, i) => (
              <span key={i} className="flex items-center gap-2">
                <span className="text-muted-foreground">{crumb}</span>
                <span className="text-muted-foreground/50">/</span>
              </span>
            ))}
            <span className="font-semibold text-foreground">{title}</span>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
