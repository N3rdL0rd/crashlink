import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: "category",
      label: "Getting Started",
      items: ["getting-started", "cli-repl", "architecture-overview"],
    },
    {
      type: "category",
      label: "Guides",
      items: [
        "decompiler-internals",
        "decompiler-notes",
        "hlasm",
        "asm-x86",
        "scripting",
        "mcp-server",
        "gui",
        "plugins",
        "patching",
        "crashtest",
      ],
    },
    {
      type: "category",
      label: "Reference",
      items: ["bytecode-primer", "roadmap", "portability"],
    },
    { type: "doc", id: "contributing", label: "Contributing" },
  ],
};

export default sidebars;
