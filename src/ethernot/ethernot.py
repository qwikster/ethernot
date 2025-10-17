import argparse
import threading
import time
import random
import asyncio
import json
import signal
import sys
import re

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText

SERVER_PORT = 6780

_animation_event = threading.Event()
_animation_thread = None

users = []

shutdown_event = asyncio.Event()

def loading_anim(): # do not call this from main thread
    symbols = [
        ["◴", "◷", "◶", "◵"],
        ["◰", "◳", "◲", "◱"],
        ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
        ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄", "▃"],
        ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"],
        ["⢎⡰", "⢎⡡", "⢎⡑", "⢎⠱", "⠎⡱", "⢊⡱", "⢌⡱", "⢆⡱"],
        ["-", "/", "\\"],
        ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[====]", "[ ===]", "[  ==]", "[   =]", "[    ]", "[   =]", "[  ==]", "[ ===]", "[====]", "[=== ]", "[==  ]", "[=   ]"],
        ["▹▹▹▹▹", "▸▹▹▹▹", "▹▸▹▹▹", "▹▹▸▹▹", "▹▹▹▸▹", "▹▹▹▹▸"]
    ]
    random.shuffle(symbols)
    while(1):
        _animation_event.wait()
        for i in symbols[1]:
            if not _animation_event.is_set():
                break
            size = (len(i) + 2)
            print(f"\x1b[{size}D", end="", flush=True)
            print(f" {i} ", end="", flush=True)
            time.sleep(0.1)

def set_loading_anim(enable: bool):
    global _animation_thread
    
    if enable:
        if _animation_thread is None or not _animation_thread.is_alive():
            _animation_thread = threading.Thread(target = loading_anim, daemon = True)
            _animation_thread.start()
        _animation_event.set()
    else:
        _animation_event.clear()
        print("\n")

def print_help():
    print_formatted_text(FormattedText([
        ("fg:#FFC600", "[ethernot/help]\n"),
        ("fg:#51DBBB", "[/quit | /exit] > "),
        ("", "Why would you want to do that?\n"),
        ("fg:#51DBBB", "[/nick <user>] > "),
        ("", "Set your username.\n"),
        ("fg:#51DBBB", "[/color #6DGHEX] > "),
        ("", "Change what you look like on others' clients.\n"),
        ("fg:#51DBBB", "[/list] > "),
        ("", "Get a list of all joinable channels. You're in ethernot/general by default.\n"),
        ("fg:#51DBBB", "[/join channel | /switch channel] > "),
        ("", "Change to a channel. Use [/list] to see which exist\n"),
        ("fg:#51DBBB", "[/create CHANNEL] > "),
        ("", "Create a channel and switch to it. Careful - irreversable, except by closing all clients.\n"),
    ]))

def list_users():
    global users
    # Replace this and implement color support
    if not users:
        userlist = FormattedText([("fg:#884444", "You're all alone...")])
    else:
        userlist = ", ".join(users)
    print_formatted_text(FormattedText([
        ("fg:#FFC600", "[ethernot/who]\n"),
        ("fg:#51DBBB", f"Currently {len(users)} clients connected.\n"),
        ("", f"Active: {userlist}"),
    ]))
    pass

async def send_loop(writer, username, session):
    color = "#9966FF"
    try:
        while not shutdown_event.is_set():
            prompt_text = FormattedText([(f"fg: {color}", f"[{username}]"), ("", " >> ")])
            try:
                line = await session.prompt_async(prompt_text)
            except KeyboardInterrupt:
                shutdown_event.set()
                break
            
            if line is None:
                continue
            line = line.strip()
            if not line:
                continue

            if line == "/help":
                print_help()
                continue
            elif line == "/who":
                list_users()
                continue
            elif line in ["/quit", "/exit", "/leave", "/disconnect", "/e", "qa!"]:
                shutdown_event.set()
                break
            elif line.startswith("name"):
                username = input("Pick a username >... ")
                continue
            elif line.startswith("/color"):
                ans = line.strip("/color ")
                if not re.match(r"^#(?:[0-9a-fA-F]{3}){1,2}$", ans):
                    print_formatted_text(FormattedText([("fg:#FF4444", "[!] Not a valid color")]))
                else:
                    color = ans
                continue

            msg = { # expand this
                "type": "message",
                "author": username,
                "color": color,
                "timestamp": time.time(),
                "body": line
            }
            try:
                writer.write((json.dumps(msg) + "\n").encode())
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError):
                print_formatted_text(FormattedText([("fg:#FF4444", "[!] Connection lost.")]))
    
    except asyncio.CancelledError:
        return
    except Exception as e:
        print_formatted_text(FormattedText([
            ("#FF4444", f"[!] issue sending: {e} (You should never see this! Report to @qwik)")
        ]))
        shutdown_event.set()
    finally:
        print_formatted_text(FormattedText([
            ("fg:#888888", "[*] Exiting ethernot. goodbye :)")
        ]))
        
async def recieve_loop(reader):
    try:
        while not shutdown_event.is_set():
            try:
                data = await reader.readline()
            except asyncio.CancelledError:
                break

            if not data:
                shutdown_event.set()
                break

            try:
                msg = json.loads(data.decode())
                author = msg.get("author", "?")
                color = msg.get("color", "#9966FF")
                body = msg.get("body", "") # check here if this breaks the input
                print_formatted_text(FormattedText([
                    (f"fg: {color}", f"[{author}]"),
                    ("", f" >> {body}")
                ]))
            except json.JSONDecodeError as e:
                print_formatted_text(FormattedText(["fg: #FF4444", f"[!] malformed message: {e}"]))

    except asyncio.CancelledError:
        return

def handle_sigint():
    if not shutdown_event.is_set():
        shutdown_event.set()

async def main():
    parser = argparse.ArgumentParser(prog="ethernot", description="EtherNOT CLI Client")
    parser.add_argument("--server", help="Server IP to connect to", required = True)
    parser.add_argument("--user", help="Username to connect under (anonymous)", required = True)
    args = parser.parse_args()
    
    username = args.user
    server = args.server
    print("\x1b[38;2;79;141;255m[i] Connecting...")
    set_loading_anim(True)

    try:
        reader, writer = await asyncio.open_connection(server, SERVER_PORT)
    except (ConnectionRefusedError, ConnectionAbortedError, ConnectionError, ConnectionResetError):
        set_loading_anim(False)
        print(f"\x1b[38;2;255;80;80m[!] Connection to {server}:{SERVER_PORT} failed. Is the server online?")
        sys.exit(0)
    
    set_loading_anim(False)
    print(f"\x1b[38;2;79;141;255m[*] Connected to {server}:{SERVER_PORT} as {username}")

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except NotImplementedError:
        print("\x1b[38;2;255;80;80m[!] something here is broken on windows, tell @qwik")
        pass

    session = PromptSession()

    with patch_stdout():
        send_task = asyncio.create_task(send_loop(writer, username, session))
        recv_task = asyncio.create_task(recieve_loop(reader))

        await shutdown_event.wait()

        for t in (send_task, recv_task):
            if not t.done():
                t.cancel()
        
        await asyncio.gather(send_task, recv_task, return_exceptions=True)

    try:
        writer.close()
        await writer.wait_closed()
        sys.exit(0) #finally lmao
    except Exception:
        pass

def entry():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        try:
            print("\x1b[0m", end="", flush=True)
        except Exception:
            pass

if __name__ == "__main__":
    entry()