# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Sphinx configuration for the shirudo documentation.

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "_ext"))

project = "shirudo"
author = "Authors of shirudo"
copyright = "2026, Authors of shirudo"

extensions = ["myst_parser", "shirudo_docs", "clickhouse_schema"]
source_suffix = {".rst": "restructuredtext"}
root_doc = "index"
exclude_patterns = ["output", "_ext", "_themes", "logos"]
language = "en"
nitpicky = True
highlight_language = "none"

html_theme = "shirudo"
html_theme_path = ["_themes"]
html_title = "shirudo documentation"
html_static_path = ["logos"]
html_favicon = "_themes/shirudo/favicon.svg"
html_sidebars = {"**": []}
html_copy_source = False
html_show_sourcelink = False
html_show_sphinx = False
html_domain_indices = False
html_use_index = False
html_permalinks_icon = "#"
html_context = {
    "repository": "https://github.com/shirudo-dev/shirudo",
    "branch": "main",
}
