# Official MCP Reference Servers

- **Original source:** https://github.com/modelcontextprotocol/servers
- **Classification:** Primary example source
- **Project snapshot summarized:** 2026-06-24

## Relevant Guidance

The official repository provides educational reference servers with tool shapes
such as filesystem access, fetching, memory, Git operations, time, and a broad
test server. These examples show how ordinary MCP tools return data that an agent
may place into model context.

## Use in This Project

- Supports the use of small read-note, fetch-like, and profile tools in the toy
  local server.
- Provides a realistic shape for indirect injection: a normal data-returning tool
  can carry attacker-controlled content.
- Helps keep the simulator representative without copying a production server.

## Limits

The project uses minimal local toy tools and does not claim feature parity with
the reference implementations.
