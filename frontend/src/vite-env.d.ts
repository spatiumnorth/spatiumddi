/// <reference types="vite/client" />

declare const __APP_VERSION__: string;

// #5022 - provided by vite-plugin-mdi.ts.
declare module "virtual:mdi-meta" {
  /** [name, aliases (space separated), tags (space separated, lowercase)] */
  const rows: [string, string, string][];
  export default rows;
}
declare module "virtual:mdi-paths/*" {
  const paths: Record<string, string>;
  export default paths;
}
