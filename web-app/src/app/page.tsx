import { redirect } from 'next/navigation';
import { LoginPage } from '@/components/login-page';
import { getSession } from '@/lib/auth/session';

interface PageProps {
  searchParams: Promise<{ error?: string }>;
}

export default async function Home({ searchParams }: PageProps) {
  const session = await getSession();
  if (session) redirect('/landing');
  const sp = await searchParams;
  return <LoginPage error={sp.error ? decodeURIComponent(sp.error) : undefined} />;
}
