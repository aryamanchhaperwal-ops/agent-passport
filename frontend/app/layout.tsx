import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AgentPassport — Runtime Security Infrastructure for Autonomous AI Agents",
  description:
    "AI proposes. Security verifies. System executes. A local reference implementation and adversarial testbed for runtime authorization and delegation security in autonomous AI-agent systems.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
