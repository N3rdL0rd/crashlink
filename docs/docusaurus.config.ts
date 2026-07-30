import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// Static (non-Docusaurus-route) content under static/ - the demo (a
// standalone Pyodide app) and the crashtest result dashboards, neither of
// which Docusaurus can generate itself. Docusaurus's navbar/footer items
// always render through its <Link> component, which client-side-routes any
// same-baseUrl-looking path whether or not it's an actual registered route -
// landing on the SPA's 404 instead of loading the real static file. The
// documented escape hatch is the `pathname://` pseudo-protocol, which tells
// <Link> to render a plain, uninterrupted <a> instead:
// https://github.com/facebook/docusaurus/issues/3309
// baseUrl is auto-prepended for any path starting with "/", so these must
// NOT include it themselves. Filenames are explicit (not trailing-slash
// directory paths) since the dev server doesn't resolve directory indexes
// the way a production static file server does. `target: "_self"` overrides
// the target="_blank" <Link> otherwise adds automatically for any link it
// considers "external" (which `pathname://` links always are, to it).
const staticPage = (path: string) => ({
  href: `pathname:///${path}`,
  target: "_self",
});

const config: Config = {
  title: "crashlink",
  tagline: "A Pure-Python HashLink bytecode Swiss Army knife",

  future: {
    v4: true,
  },

  url: "https://n3rdl0rd.github.io",
  baseUrl: "/crashlink/",

  organizationName: "N3rdL0rd",
  projectName: "crashlink",

  onBrokenLinks: "warn",
  onBrokenMarkdownLinks: "warn",

  markdown: {
    // The griffe-generated reference (.md) is plain docstring prose that
    // freely contains bare `<...>` text; parsing it as full MDX/JSX would
    // require escaping every angle bracket. `.mdx` pages (the landing page)
    // still get real JSX.
    format: "detect",
  },

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          id: "docs",
          path: "content/docs",
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          editUrl: "https://github.com/N3rdL0rd/crashlink/tree/main/docs/content/docs/",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "reference",
        path: "content/reference",
        routeBasePath: "reference",
        sidebarPath: "./sidebarsReference.ts",
        editUrl: "https://github.com/N3rdL0rd/crashlink/tree/main/docs/gen_reference.py",
        editCurrentVersion: true,
      },
    ],
  ],

  themeConfig: {
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: "crashlink",
      items: [
        {
          type: "docSidebar",
          docsPluginId: "docs",
          sidebarId: "docsSidebar",
          label: "Docs",
          position: "left",
        },
        {
          type: "docSidebar",
          docsPluginId: "reference",
          sidebarId: "referenceSidebar",
          label: "Reference",
          position: "left",
        },
        { to: "/results", label: "crashtest", position: "left" },
        { label: "Demo", position: "right", ...staticPage("demo/index.html") },
        {
          href: "https://github.com/N3rdL0rd/crashlink",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Decompiler Notes", to: "/decompiler" },
            { label: "Contributing", to: "/contributing" },
            { label: "crashtest", to: "/results" },
          ],
        },
        {
          title: "API Reference",
          items: [
            { label: "crashlink", to: "/reference/crashlink" },
            { label: "hlrun", to: "/reference/hlrun" },
            { label: "crashtest", to: "/reference/crashtest" },
          ],
        },
        {
          title: "More",
          items: [
            { label: "GitHub", href: "https://github.com/N3rdL0rd/crashlink" },
            { label: "PyPI", href: "https://pypi.org/project/crashlink/" },
          ],
        },
      ],
      copyright: `Project by N3rdL0rd | Licensed under the MIT License.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
