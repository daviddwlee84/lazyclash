# SVG export for routing topology

Status: deferred at user request (2026-09-22)
Priority: P?
Effort: M

The first topology version exports Mermaid and JSON and embeds the Go
mermaid-ascii renderer for terminal use. Direct SVG export is intentionally
deferred; do not add Node, Chromium, or automatic tool installation now.

The researched follow-up is optional local `mmdc` from
[mermaid-cli](https://github.com/mermaid-js/mermaid-cli), using the same generated
Mermaid graph. [termaid](https://github.com/fasouto/termaid) is an alternative
Python terminal renderer, not needed by the built-in Go path.

When SVG is requested, add a renderer adapter that reports missing local tools,
uses argument arrays/private temporary input, honors cancellation, and writes
only the requested output path. Decide installation/distribution expectations
then; keep terminal and Mermaid export usable without the optional renderer.
Validate labels, runtime-selection annotations, large graphs and SVG output
visually. Never embed raw configuration or credential values in an export.
