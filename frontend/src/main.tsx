import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";

import { queryClient } from "@/lib/queryClient";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { safeLocalStorage } from "@/lib/safeStorage";
import App from "./App";
import "./index.css";

// Apply saved theme before first render to prevent flash. Storage the
// browser refuses (site data blocked) reads as nothing saved, so the
// system theme applies and the console still starts (#3231).
(function () {
  const saved = safeLocalStorage.getItem("theme") ?? "system";
  const resolved =
    saved === "system"
      ? window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : saved;
  document.documentElement.classList.toggle("dark", resolved === "dark");
})();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary
          fallback={
            <div className="flex min-h-screen flex-col items-center justify-center bg-background p-6 text-center">
              <h1 className="text-lg font-semibold">Something went wrong</h1>
              <p className="mt-2 text-sm text-muted-foreground">
                The application crashed. Please reload the page.
              </p>
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="mt-4 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
              >
                Reload
              </button>
            </div>
          }
        >
          <App />
        </ErrorBoundary>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </BrowserRouter>
  </StrictMode>,
);
