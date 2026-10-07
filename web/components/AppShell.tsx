"use client";

import clsx from "clsx";
import {
  BellRing,
  BrainCircuit,
  LayoutDashboard,
  Menu,
  Network,
  ScanSearch,
  ShieldCheck,
  X,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import MlStatus from "@/components/MlStatus";

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scan", label: "Threat Scanner", icon: ScanSearch },
  { href: "/network", label: "Network Analyzer", icon: Network },
  { href: "/alerts", label: "Alerts", icon: BellRing },
  { href: "/models", label: "Models", icon: BrainCircuit },
];

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-400 shadow-glow">
        <ShieldCheck size={20} />
      </span>
      <span className="text-lg font-bold tracking-tight text-white">
        Cyber<span className="text-emerald-400">Shield</span>
      </span>
    </Link>
  );
}

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();

  return (
    <nav className="mt-8 flex flex-col gap-1">
      {NAV.map(({ href, label, icon: Icon }) => {
        const active =
          href === "/" ? pathname === "/" : pathname.startsWith(href);

        return (
          <Link
            key={href}
            href={href}
            onClick={onNavigate}
            className={clsx(
              "flex items-center gap-3 rounded-lg border px-3 py-2.5 text-sm font-medium transition",
              active
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                : "border-transparent text-slate-400 hover:bg-soc-raised hover:text-white",
            )}
          >
            <Icon size={18} />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}

function SidebarBody({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="flex h-full flex-col">
      <Brand />
      <NavLinks onNavigate={onNavigate} />

      <div className="mt-auto space-y-3 pt-6">
        <MlStatus />
        <p className="px-1 text-[10px] uppercase tracking-widest text-soc-muted">
          SDG 9 &middot; SDG 16
        </p>
      </div>
    </div>
  );
}

export default function AppShell({
  children,
}: {
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <div className="min-h-screen lg:pl-64">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-soc-line bg-soc-panel/95 p-5 backdrop-blur lg:block">
        <SidebarBody />
      </aside>

      <header className="sticky top-0 z-20 flex items-center justify-between border-b border-soc-line bg-soc-panel/95 px-4 py-3 backdrop-blur lg:hidden">
        <Brand />

        <button
          type="button"
          aria-label="Open menu"
          onClick={() => setOpen(true)}
          className="rounded-lg border border-soc-line p-2 text-slate-300"
        >
          <Menu size={20} />
        </button>
      </header>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setOpen(false)}
          />

          <div className="absolute inset-y-0 left-0 w-72 border-r border-soc-line bg-soc-panel p-5">
            <button
              type="button"
              aria-label="Close menu"
              onClick={() => setOpen(false)}
              className="absolute right-3 top-3 rounded-lg p-2 text-slate-400 hover:text-white"
            >
              <X size={18} />
            </button>

            <SidebarBody onNavigate={() => setOpen(false)} />
          </div>
        </div>
      )}

      <main className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        {children}
      </main>
    </div>
  );
}
