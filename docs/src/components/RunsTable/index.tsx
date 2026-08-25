import React, { useEffect, useState } from "react";
import useBaseUrl from "@docusaurus/useBaseUrl";
import type { RunSummary } from "./types";
import styles from "./styles.module.css";

function formatSimilarity(avg: number | null): string {
  if (avg === null) {
    return "—";
  }
  return `${(avg * 100).toFixed(1)}%`;
}

export default function RunsTable(): React.ReactElement {
  const dataUrl = useBaseUrl("/crashtest-runs.json");
  const runBaseUrl = useBaseUrl("/crashtest_out/run/");
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(dataUrl)
      .then((res) => {
        if (!res.ok) {
          throw new Error(`${res.status} ${res.statusText}`);
        }
        return res.json();
      })
      .then(setRuns)
      .catch((err) => setError(String(err)));
  }, [dataUrl]);

  if (error) {
    return <p>Failed to load run data: {error}</p>;
  }

  if (runs === null) {
    return <p>Loading runs…</p>;
  }

  return (
    <div className={styles.tableWrapper}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>Run</th>
            <th>crashlink</th>
            <th>Commit</th>
            <th>Status</th>
            <th>Cases</th>
            <th>Avg. Similarity</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.id}>
              <td>
                {/* Plain <a>, not <Link>: run detail pages are static passthrough
                    HTML, not a Docusaurus route, so client-side routing would
                    404 them - see docusaurus.config.ts's `staticPage` helper. */}
                <a href={`${runBaseUrl}${run.id}/index.html`}>{run.timestamp}</a>
                {run.git.dirty && <span className={styles.dirtyBadge}>dirty</span>}
              </td>
              <td>{run.version}</td>
              <td>
                {run.git.is_release ? (
                  <span className={styles.muted}>release build</span>
                ) : run.git.github ? (
                  <a href={run.git.github}>
                    {run.git.branch}@{run.git.commit}
                  </a>
                ) : (
                  <span className={styles.muted}>—</span>
                )}
              </td>
              <td style={{ color: run.status_color }}>{run.status}</td>
              <td>{run.case_count}</td>
              <td>{formatSimilarity(run.avg_similarity)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
