import type { Metadata } from "next";
import { Syne, DM_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const syne = Syne({
  subsets:  ["latin"],
  variable: "--font-display",
  weight:   ["400", "500", "600", "700", "800"],
});

const dmSans = DM_Sans({
  subsets:  ["latin"],
  variable: "--font-body",
  weight:   ["300", "400", "500"],
});

const jetBrainsMono = JetBrains_Mono({
  subsets:  ["latin"],
  variable: "--font-mono",
  weight:   ["300", "400", "500"],
});

export const metadata: Metadata = {
  title:       "SENTINEL — Web Vulnerability Scanner",
  description: "Automated Web Vulnerability Scanner with Explainable AI",
  icons:       { icon: "/favicon.ico" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body
        className={`
          ${syne.variable} ${dmSans.variable} ${jetBrainsMono.variable}
          font-body bg-void text-bright antialiased min-h-screen
        `}
      >
        {children}
      </body>
    </html>
  );
}
