"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

const links = [
  ["/", "Overview"],
  ["/alerts", "Alert Queue"],
  ["/incidents", "Incidents"],
  ["/assets", "Protected Assets"],
  ["/honeypot", "Honeypot Intelligence"],
  ["/sources", "Telemetry Sources"],
  ["/blindness", "Blindness Map"],
  ["/rules", "Detection Rules"],
  ["/simulations", "Validation Runs"],
  ["/noise-rules", "Noise Policies"],
  ["/integrations", "Integrations"],
];

export default function Shell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();

  function logout() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    router.push("/login");
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          TRUST-SOC
          <small>REAL-TIME SECURITY ASSURANCE</small>
        </div>
        <nav className="nav">
          {links.map(([href, label]) => (
            <Link key={href} href={href} className={pathname === href ? "active" : ""}>
              {label}
            </Link>
          ))}
          <a
            href="#"
            onClick={(event) => {
              event.preventDefault();
              logout();
            }}
          >
            Sign out
          </a>
        </nav>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
