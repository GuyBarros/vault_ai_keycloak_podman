import { redirect } from 'next/navigation';
import { Header } from '@/components/header';
import { FlowStrip } from '@/components/chat/flow-strip';
import { ChatWorkspace } from '@/components/chat/chat-workspace';
import { getSession } from '@/lib/auth/session';
import { InstanaUserTracker } from '@/components/instana-user-tracker';

export const dynamic = 'force-dynamic';

export default async function LandingPage() {
  const session = await getSession();
  if (!session?.user_info) redirect('/');

  const username = session.preferred_username || session.user_info.name || '';

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header username={username} />
      <FlowStrip />
      <ChatWorkspace username={username} />
      <InstanaUserTracker user={username} />
    </div>
  );
}
