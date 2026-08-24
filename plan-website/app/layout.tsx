import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'תוכנית העבודה הסופית — MCP Security',
  description: 'תוכנית העבודה המשותפת של נעם ואור לפרויקט MCP Attack & Defense Simulator',
  openGraph: {
    title: 'תוכנית העבודה הסופית — MCP Security',
    description: 'מפרוטוטייפ עובד למחקר מדיד: חלוקת העבודה והדרך קדימה של נעם ואור.',
    locale: 'he_IL',
    type: 'website',
    images: [{ url: '/mcp-security-plan-og.png', width: 1200, height: 630, alt: 'MCP Security — תוכנית עבודה סופית' }],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="he" dir="rtl"><body>{children}</body></html>;
}
