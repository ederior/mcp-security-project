# SecureNotes MCP Server

This project is a defensive cyber security lab project for testing MCP server security.

## Stage A - Basic MCP Server

The server exposes several MCP tools over Streamable HTTP:

- health_check
- list_notes
- read_note
- search_notes
- get_user_profile

The server uses only fake in-memory data.

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
install depenncies:
pip install -r requirements.txt
RUN the server:
python server.py
The server runs on:
http://127.0.0.1:8000/mcp
Testing with MCP Inspector
Run MCP Inspector:
npx -y @modelcontextprotocol/inspector
