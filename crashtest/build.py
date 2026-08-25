"""
Functions to build the crashtest results site.
"""

import json
import os

from staticjinja import Site

from .models import load_runs


def build() -> None:
    """
    Build the site: per-run detail pages under docs/static/crashtest_out/,
    and a lightweight run summary index consumed by the Docusaurus results
    table at docs/static/crashtest-runs.json.
    """
    template_path = os.path.join(os.path.dirname(__file__), "templates")
    runs = load_runs(os.path.join(os.path.dirname(__file__), "runs"))
    site = Site.make_site(searchpath=template_path, outpath="docs/static/crashtest_out")
    for run in runs:
        context = {"context": run.context, "git": run.git, "cases": run.cases}

        template = site.get_template("_result.html")
        output_path = f"docs/static/crashtest_out/run/{run.id}/index.html"
        site.render_template(template, context=context, filepath=output_path)

    summary = [run.to_summary_json() for run in sorted(runs, key=lambda r: r.id, reverse=True)]
    with open("docs/static/crashtest-runs.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
