import os
import subprocess
import sys


def print_help() -> None:
    print()
    print("Available commands:")
    print("  /help      Show this help menu")
    print("  /secure    Switch to secure mode")
    print("  /unsafe    Switch to unsafe mode")
    print("  /mode      Show current security mode")
    print("  /exit      Exit the chat")
    print()


def main() -> None:
    security_mode = os.environ.get("SECURITY_MODE", "secure")

    print("=" * 70)
    print("Gemini + MCP Interactive Terminal Chat")
    print("=" * 70)
    print(f"Current security mode: {security_mode}")
    print("Type /help for commands.")
    print("Type /exit to quit.")
    print()

    while True:
        try:
            prompt = input(f"mcp-chat[{security_mode}]> ").strip()
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except EOFError:
            print("\nExiting.")
            break

        if not prompt:
            continue

        if prompt in ["/exit", "/quit"]:
            print("Goodbye.")
            break

        if prompt == "/help":
            print_help()
            continue

        if prompt == "/mode":
            print(f"Current security mode: {security_mode}")
            continue

        if prompt == "/secure":
            security_mode = "secure"
            print("Switched to secure mode.")
            continue

        if prompt == "/unsafe":
            security_mode = "unsafe"
            print("Switched to unsafe mode.")
            continue

        env = os.environ.copy()
        env["SECURITY_MODE"] = security_mode
        env["PYTHONUNBUFFERED"] = "1"

        print()

        subprocess.run(
            [sys.executable, "ai_client.py", prompt],
            env=env,
            text=True,
        )

        print()


if __name__ == "__main__":
    main()
