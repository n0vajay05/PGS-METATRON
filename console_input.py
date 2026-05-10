import os
import sys


class MenuBack(Exception):
    pass


KEY_UP = "up"
KEY_DOWN = "down"
KEY_ENTER = "enter"
KEY_ESCAPE = "escape"
KEY_CTRL_C = "ctrl_c"


def _ask_exit_windows() -> bool:
    import msvcrt

    prompt = "\nClose Metatron? [y/N]: "
    sys.stdout.write(prompt)
    sys.stdout.flush()
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            return False
        if ch == "\x1b":
            sys.stdout.write("\n")
            sys.stdout.flush()
            return False
        if ch in ("\x03",):
            sys.stdout.write("\n")
            sys.stdout.flush()
            return True
        if ch.lower() == "y":
            sys.stdout.write("y\n")
            sys.stdout.flush()
            return True
        if ch.lower() == "n":
            sys.stdout.write("n\n")
            sys.stdout.flush()
            return False


def _prompt_windows(text: str) -> str:
    import msvcrt

    while True:
        buffer = []
        sys.stdout.write(f"\033[36m{text}\033[0m")
        sys.stdout.flush()
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                sys.stdout.write("\n")
                sys.stdout.flush()
                return "".join(buffer).strip()
            if ch == "\x1b":
                sys.stdout.write("\n")
                sys.stdout.flush()
                raise MenuBack()
            if ch == "\x03":
                if _ask_exit_windows():
                    print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
                    raise SystemExit(0)
                sys.stdout.write(f"\033[36m{text}\033[0m" + "".join(buffer))
                sys.stdout.flush()
                continue
            if ch in ("\b", "\x7f"):
                if buffer:
                    buffer.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            if ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue
            buffer.append(ch)
            sys.stdout.write(ch)
            sys.stdout.flush()


def prompt(text: str) -> str:
    if os.name == "nt":
        return _prompt_windows(text)

    try:
        return input(f"\033[36m{text}\033[0m").strip()
    except KeyboardInterrupt:
        answer = input("\nClose Metatron? [y/N]: ").strip().lower()
        if answer == "y":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            raise SystemExit(0)
        raise MenuBack()


def read_menu_key() -> tuple[str, str]:
    """Return a normalized menu key plus the raw character for printable input."""
    if os.name == "nt":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            return KEY_ENTER, ""
        if ch == "\x1b":
            return KEY_ESCAPE, ""
        if ch == "\x03":
            return KEY_CTRL_C, ""
        if ch in ("\x00", "\xe0"):
            code = msvcrt.getwch()
            if code == "H":
                return KEY_UP, ""
            if code == "P":
                return KEY_DOWN, ""
            return "", ""
        return "", ch

    try:
        value = input().strip()
    except KeyboardInterrupt:
        return KEY_CTRL_C, ""
    if not value:
        return KEY_ENTER, ""
    return "", value


def ask_exit_from_menu() -> None:
    if os.name == "nt":
        if _ask_exit_windows():
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            raise SystemExit(0)
        return

    answer = input("\nClose Metatron? [y/N]: ").strip().lower()
    if answer == "y":
        print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
        raise SystemExit(0)


def pause(text: str = "\n\033[90mPress Enter to continue...\033[0m") -> None:
    try:
        prompt(text)
    except MenuBack:
        return
