import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "TRUST-SOC",
  description: "Tamper-resilient telemetry and SOC validation"
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
