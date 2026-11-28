// ESLint v10 flat config — minimal setup for React + TypeScript + Vite.
// Migrated from the implicit legacy .eslintrc since the repo only declares
// eslint-plugin-react-hooks + eslint-plugin-react-refresh + typescript-eslint.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  {
    ignores: ["dist", "build", "node_modules", "coverage", "*.config.js", "*.config.ts"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    // Don't flag eslint-disable directives that are now redundant — the rules
    // they target may have been turned off globally.
    linterOptions: { reportUnusedDisableDirectives: false },
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // eslint-plugin-react-hooks 7 added React-Compiler-oriented rules to
      // `recommended`. They flag established patterns here (sessionStorage /
      // prop-sync effects, ref reads, Date.now() in render) and fixing them
      // means restructuring components, so they are off until that pass is
      // done (follow-up issue). Findings at the 7.x bump: set-state-in-effect
      // 79, purity 15, refs 14, globals 5, static-components 2.
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/purity": "off",
      "react-hooks/refs": "off",
      "react-hooks/globals": "off",
      "react-hooks/static-components": "off",
      // ESLint 10 core `recommended` addition: 13 findings, all the
      // `let x = default; try { x = parse() } catch {}` idiom — intentional
      // defaults, not bugs. Off rather than churn 10 files.
      "no-useless-assignment": "off",
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // Off project-wide: these are sessionStorage-sync effects and stable
      // setter functions we deliberately omit from deps. Toggling them on
      // would force code restructuring without any real safety win.
      "react-hooks/exhaustive-deps": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    // shadcn-style UI primitives intentionally re-export Radix primitives
    // alongside components (`export const X = SomePrimitive.Y`), which newer
    // eslint-plugin-react-refresh flags as a mixed-export fast-refresh hazard.
    // Fast-refresh granularity is irrelevant for these stable wrappers, so
    // turn the rule off for the ui/ primitives only.
    files: ["src/components/ui/**/*.{ts,tsx}"],
    rules: {
      "react-refresh/only-export-components": "off",
    },
  },
);
