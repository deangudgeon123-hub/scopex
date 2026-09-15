import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SCOPEX — Website Security Made Simple",
  description: "A clean security dashboard for discovering, understanding and fixing website vulnerabilities.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
