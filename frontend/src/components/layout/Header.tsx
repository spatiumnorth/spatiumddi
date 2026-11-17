import { useAuth } from "@/hooks/useAuth";
import { useTheme } from "@/hooks/useTheme";
import { Link, useNavigate } from "react-router-dom";
import { Code2, LogOut, Menu, Moon, Sun, UserCircle2 } from "lucide-react";
import { GlobalSearch } from "@/components/GlobalSearch";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsOverlay";

export function Header({
  onMobileMenu,
  mobileNavOpen = false,
}: {
  onMobileMenu?: () => void;
  mobileNavOpen?: boolean;
}) {
  const { logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <header className="flex h-14 items-center border-b bg-card px-3 sm:px-6 gap-2 sm:gap-3">
      {/* Hamburger — only shown below md breakpoint */}
      <button
        type="button"
        onClick={onMobileMenu}
        aria-label="Open navigation"
        aria-expanded={mobileNavOpen}
        aria-controls="app-sidebar"
        className="md:hidden rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
      >
        <Menu className="h-5 w-5" />
      </button>
      <div className="flex-1" />
      <GlobalSearch />
      <div className="flex items-center gap-1">
        {/* Issue #81 — the ``?`` overlay's discoverable affordance. Same
            reasoning as the API-docs link below: the keyboard route
            exists, this is how you find out it exists. */}
        <KeyboardShortcutsHelp />
        {/* Issue #96 — discoverable API docs link for power users.
            Sidebar has the labeled entry; this is the muscle-memory
            shortcut. ReDoc is the primary surface (cleaner browsing);
            operators who want Swagger UI can take the sidebar entry
            or jump from ReDoc. */}
        <a
          href="/api/redoc"
          target="_blank"
          rel="noopener noreferrer"
          title="API documentation (opens in new tab)"
          className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        >
          <Code2 className="h-4 w-4" />
        </a>
        <Link
          to="/account"
          title="Account — password & two-factor"
          className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        >
          <UserCircle2 className="h-4 w-4" />
        </Link>
        <button
          onClick={toggleTheme}
          title={
            theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
          }
          className="rounded-md p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        >
          {theme === "dark" ? (
            <Sun className="h-4 w-4" />
          ) : (
            <Moon className="h-4 w-4" />
          )}
        </button>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2 rounded-md px-2 sm:px-3 py-1.5 text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        >
          <LogOut className="h-4 w-4" />
          <span className="hidden sm:inline">Sign out</span>
        </button>
      </div>
    </header>
  );
}
