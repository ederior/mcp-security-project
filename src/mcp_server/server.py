import logging
from datetime import UTC, datetime

from mcp.server.fastmcp import FastMCP

from mcp_server.events import fingerprint

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("SecureNotes Lab MCP Server")


USERS: dict[str, dict[str, str]] = {
    "user_1": {
        "user_id": "user_1",
        "name": "Alice Cohen",
        "role": "student",
        "department": "Electrical and Computer Engineering",
    },
    "user_2": {
        "user_id": "user_2",
        "name": "Bob Levi",
        "role": "admin",
        "department": "Cyber Lab",
    },
}

NOTES: dict[str, dict[str, str]] = {
    "note_1": {
        "note_id": "note_1",
        "owner_id": "user_1",
        "title": "Project Plan",
        "content": "This note contains the initial MCP project plan.",
    },
    "note_2": {
        "note_id": "note_2",
        "owner_id": "user_1",
        "title": "Meeting Summary",
        "content": "We decided to build a safe MCP server and test it later.",
    },
    "note_3": {
        "note_id": "note_3",
        "owner_id": "user_2",
        "title": "Admin Note",
        "content": "This is fake admin data for lab testing only.",
    },
    "note_4": {
        "note_id": "note_4",
        "owner_id": "user_1",
        "title": "External Security Report",
        "content": (
            "This external report describes safe testing practices "
            "for MCP tools and untrusted external data."
        ),
    },
}


def audit_log(action: str, details: str) -> None:
    timestamp = datetime.now(UTC).isoformat()

    logger.info(
        "[%s] action=%s details_length=%d details_fingerprint=%s",
        timestamp,
        action,
        len(details),
        fingerprint(details),
    )


def validate_text(value: str, max_len: int = 100) -> bool:
    if not isinstance(value, str):
        return False

    return len(value) <= max_len


@mcp.tool()
def health_check() -> dict[str, str]:
    """Check if the MCP server is running."""
    audit_log("health_check", "Server health check requested")

    return {
        "status": "ok",
        "server": "SecureNotes Lab MCP Server",
        "purpose": "Defensive MCP security testing project",
    }


@mcp.tool()
def list_notes(user_id: str) -> list[dict[str, str]]:
    """List notes that belong to a specific user."""
    audit_log("list_notes", f"user_id={user_id}")

    if not validate_text(user_id, max_len=30):
        return [{"error": "Invalid user_id"}]

    result = []

    for note in NOTES.values():
        if note["owner_id"] == user_id:
            result.append(
                {
                    "note_id": note["note_id"],
                    "title": note["title"],
                    "owner_id": note["owner_id"],
                }
            )

    return result


@mcp.tool()
def read_note(note_id: str) -> dict[str, str]:
    """Read a note by note_id."""
    audit_log("read_note", f"note_id={note_id}")

    if not validate_text(note_id, max_len=30):
        return {"error": "Invalid note_id"}

    note = NOTES.get(note_id)

    if note is None:
        return {"error": "Note not found"}

    return note


@mcp.tool()
def search_notes(query: str) -> list[dict[str, str]]:
    """Search notes by title or content."""
    audit_log("search_notes", f"query={query}")

    if not validate_text(query, max_len=100):
        return [{"error": "Invalid search query"}]

    query_lower = query.lower()
    result = []

    for note in NOTES.values():
        title = note["title"].lower()
        content = note["content"].lower()

        if query_lower in title or query_lower in content:
            result.append(
                {
                    "note_id": note["note_id"],
                    "title": note["title"],
                    "owner_id": note["owner_id"],
                }
            )

    return result


@mcp.tool()
def get_user_profile(user_id: str) -> dict[str, str]:
    """Get a fake user profile by user_id."""
    audit_log("get_user_profile", f"user_id={user_id}")

    if not validate_text(user_id, max_len=30):
        return {"error": "Invalid user_id"}

    user = USERS.get(user_id)

    if user is None:
        return {"error": "User not found"}

    return user


@mcp.resource("lab://project-info")
def project_info() -> str:
    """General project information resource."""
    return (
        "This MCP server is used for a defensive cyber security project. "
        "It contains only fake data and is intended for controlled testing."
    )


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
