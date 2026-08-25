from mcp_server.server import (
    get_user_profile,
    health_check,
    list_notes,
    read_note,
    search_notes,
)


def test_health_check():
    result = health_check()

    assert result["status"] == "ok"
    assert result["server"] == "SecureNotes Lab MCP Server"


def test_list_notes_for_user_1():
    result = list_notes("user_1")

    note_ids = {note["note_id"] for note in result}

    assert note_ids == {"note_1", "note_2", "note_4"}


def test_read_note():
    result = read_note("note_1")

    assert result["note_id"] == "note_1"
    assert result["owner_id"] == "user_1"
    assert result["title"] == "Project Plan"


def test_search_notes():
    result = search_notes("Admin")

    assert len(result) == 1
    assert result[0]["note_id"] == "note_3"
    assert result[0]["owner_id"] == "user_2"


def test_get_user_profile():
    result = get_user_profile("user_2")

    assert result["user_id"] == "user_2"
    assert result["name"] == "Bob Levi"
    assert result["role"] == "admin"
