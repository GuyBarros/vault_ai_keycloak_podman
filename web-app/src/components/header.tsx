import { AiAgentLogo } from '@/components/ai-agent-logo';
import { UserIcon } from '@/components/icons';
import { ThemeSelect } from '@/components/theme-select';
import { LogoutButton } from '@/components/logout-button';

interface Props {
  username: string;
}

export function Header({ username }: Props) {
  return (
    <header className="app-header" role="banner">
      <div className="app-header__left">
        <div className="app-header__brand">
          <AiAgentLogo
            size={28}
            color="#ffffff"
            accent="#4589ff"
            className="app-header__brand-mark"
          />
          <span className="app-header__product">AI Runtime Security</span>
        </div>
        <nav className="app-header__nav" aria-label="Primary">
          <a className="is-active" href="/landing">
            Chat
          </a>
        </nav>
      </div>
      <div className="app-header__right">
        <div className="app-header__user">
          <span className="app-header__avatar" aria-hidden="true">
            <UserIcon size={16} />
          </span>
          <span className="app-header__username">{username}</span>
        </div>
        <ThemeSelect />
        <LogoutButton />
      </div>
    </header>
  );
}
