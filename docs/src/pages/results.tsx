import React from "react";
import Layout from "@theme/Layout";
import RunsTable from "@site/src/components/RunsTable";

export default function Results(): React.ReactElement {
  return (
    <Layout title="Decompiler Test Results" description="crashtest regression suite results">
      <main className="container margin-vert--lg">
        <h1>Decompiler Test Results</h1>
        <p>
          crashtest is a built-in regression suite for crashlink that scores the decompiler&apos;s output
          by recompiling it and comparing opcodes against the original bytecode. Run it with{" "}
          <code>just test</code> (full suite including pytest) or <code>crashtest auto</code> /{" "}
          <code>python -m crashtest auto</code> from the repo root.
        </p>
        <p>
          Each run recompiles every decompiled test case with <code>haxe</code> and scores method-level
          opcode similarity; cases below 90% similarity are marked as failures. Click a run to see its
          per-case original source, decompiled output, IR, and opcode diff.
        </p>
        <RunsTable />
      </main>
    </Layout>
  );
}
