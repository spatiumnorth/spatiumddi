import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { Modal } from "@/components/ui/modal";
import { useAuth } from "@/hooks/useAuth";
import {
  idleSchedule,
  idleSeconds,
  noteInteraction,
  startActivityTracking,
  unreportedInteractionMs,
} from "@/lib/activity";
import { authApi, settingsApi } from "@/lib/api";
import { setAccessToken } from "@/lib/authToken";

function formatRemaining(seconds: number): string {
  const s = Math.max(0, Math.ceil(seconds));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

/**
 * Applies Settings → Sessions in the console: shows the Auto-Logout Warning
 * and signs out when the Session Timeout runs out. The server refuses an
 * idle session on its own (``backend/app/core/session_idle.py``); this is
 * what the operator sees, so they get a warning and the login page rather
 * than a request failing under them.
 */
export function IdleLogout() {
  const { logout } = useAuth();
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
    staleTime: 5 * 60_000,
    refetchOnWindowFocus: false,
  });
  const schedule = idleSchedule(
    settings?.session_timeout_minutes,
    settings?.auto_logout_minutes,
  );
  const [idle, setIdle] = useState(0);

  useEffect(() => {
    startActivityTracking();
  }, []);

  const logoutAt = schedule?.logoutAt ?? 0;
  useEffect(() => {
    if (logoutAt <= 0) return;
    // Tell the server about interaction that produced no request (reading,
    // typing into a form), so it does not expire a session the operator is
    // using. A quarter of the timeout, at most once a minute.
    const reportEveryMs = Math.min(60_000, (logoutAt * 1000) / 4);
    const tick = window.setInterval(() => {
      const current = idleSeconds();
      setIdle(current);
      if (current >= logoutAt) {
        window.clearInterval(tick);
        // The server already refuses this session; drop the token and go to
        // the login page. Not /auth/logout, which would also end the
        // operator's sessions on other devices.
        setAccessToken(null);
        if (!window.location.pathname.startsWith("/login")) {
          window.location.href = "/login";
        }
        return;
      }
      if (unreportedInteractionMs() >= reportEveryMs) {
        void authApi.me().catch(() => {
          // A failed report is retried on the next tick.
        });
      }
    }, 1000);
    return () => window.clearInterval(tick);
  }, [logoutAt]);

  if (!schedule || schedule.warnAt === null || idle < schedule.warnAt) {
    return null;
  }

  const stay = () => {
    noteInteraction();
    setIdle(0);
    void authApi.me().catch(() => {
      // Nothing to do: the next tick reports again or signs out.
    });
  };

  return (
    <Modal title="Session about to expire" onClose={stay}>
      <p className="text-sm">
        You will be signed out in{" "}
        <strong>{formatRemaining(schedule.logoutAt - idle)}</strong> because of
        inactivity.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={() => {
            void logout().finally(() => {
              window.location.href = "/login";
            });
          }}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
        >
          Sign out now
        </button>
        <button
          type="button"
          onClick={stay}
          className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Stay signed in
        </button>
      </div>
    </Modal>
  );
}
