"""
Functions to build the crashtest results site.
"""
from staticjinja import Site # type: ignore
import os
from .models import load_runs


def build() -> None:
    """
    Build the site.
    """
    template_path = os.path.join(os.path.dirname(__file__), "templates")
    runs = load_runs(os.path.join(os.path.dirname(__file__), "runs"))
    contexts = [
        ('index.html', {
            "runs": runs,
        })
    ]
    site = Site.make_site(searchpath=template_path,
                          outpath="docs/crashtest_out", contexts=contexts)
    for run in runs:
        context = {
            "context": run.context,
            "git": run.git, 
            "cases": run.cases
        }
        
        template = site.get_template("_result.html")
        output_path = f"docs/crashtest_out/run/{run.id}/index.html"
        site.render_template(template, context=context, filepath=output_path)
    site.render()