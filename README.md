# AI Sec Watch tools

Check your AI dependencies before you ship. This repository holds the public tools for
[AI Sec Watch](https://aisecwatch.com): a GitHub Action, a command-line tool and the MCP server
listing. They all call the same open service, Stack Check, which reports for a project's
dependency files:

- known vulnerabilities in the exact versions you pin (from [OSV](https://osv.dev)), with fixed versions;
- the LLM SDKs, agent frameworks, MCP and retrieval components in the tree;
- dependencies that reach an LLM component indirectly, from the
  [Exposure Registry](https://aisecwatch.com/packages);
- the host authority your dependencies hand to a model (shell, file system, browser, outbound HTTP,
  code execution, MCP tools);
- the controls that follow, each with the fact that triggered it.

Supported files: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
`package.json`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml`,
`go.sum`, `go.mod`, `Cargo.lock`, `Cargo.toml`, and CycloneDX or SPDX JSON SBOMs (components with
PyPI, npm, Go or crates.io package URLs). Lockfiles and SBOMs give version-exact results.

Output can also be a CycloneDX 1.6 AI-BOM: the LLM SDKs, agent frameworks and MCP components in
use, the dependencies that reach one indirectly with their path, and the vulnerabilities found,
with AI Sec Watch fields as `aisecwatch:` properties.

## GitHub Action

```yaml
name: Stack Check
on: [pull_request, push]
permissions:
  contents: read
  security-events: write
jobs:
  stack-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jackluucoding/aisecwatch-tools@v0
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: stack-check.sarif
```

The report appears in the job summary; findings appear in the repository's code scanning alerts.

## Command line

```sh
npx aisecwatch-stack-check                   # finds lockfiles in the current directory
npx aisecwatch-stack-check poetry.lock --fail-on critical --sarif out.sarif
npx aisecwatch-stack-check sbom.cdx.json --cyclonedx ai-bom.cdx.json
```

Exit codes: 0 no advisory at or above `--fail-on`; 1 at least one; 2 the check could not run.

## MCP server

Add `https://aisecwatch.com/api/mcp` as a remote MCP server (Streamable HTTP) in your coding
assistant. Tools: `check_stack`, `check_llm_exposure`, `search_issues`, `get_issue`, `scan_stack`,
`latest_digest`. `server.json` describes the server for the official MCP registry; validate and
publish it with the registry's `mcp-publisher` tool.

## Privacy

Files are sent to the Stack Check API, processed in memory and not stored. With the vulnerability
lookup on (default), package names and pinned versions are sent to OSV. Turn it off with
`osv: false` or `--no-osv`. See [privacy](https://aisecwatch.com/privacy) and
[terms](https://aisecwatch.com/terms).

## License

Functional Source License 1.1 with an MIT future license (FSL-1.1-MIT). See `LICENSE`.
