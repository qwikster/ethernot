import argparse
import threading
import sys
import time
import random
import asyncio
import json

SERVER_PORT = 6780

_animation_event = threading.Event()
_animation_thread = None

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

async def send_loop(writer, username):
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline) # should be non-blocking
        line = line.strip()
        if not line:
            continue
        
        msg = { # expand this
            "type": "chat",
            "author": username,
            "timestamp": time.time(),
            "body": line
        }
        writer.write((json.dumps(msg) + "\n").encode())
        await writer.drain()
        
async def recieve_loop(reader):
    while data := await reader.readline():
        try:
            msg = json.loads(data.decode())
            author = msg.get("author", "?")
            body = msg.get("body", "") 
            print(f"\x1b[38;2;79;141;255m[{author}] \x1b[38;2;255;255;255m>> {body}")
        except json.JSONDecodeError as e:
            print(f"\x1b[38;2;255;80;80m[!] malformed message: {e}")

async def main():
    parser = argparse.ArgumentParser(prog="ethernot", description="EtherNOT CLI Client")
    parser.add_argument("--server", help="Server IP to connect to", required = True)
    parser.add_argument("--user", help="Username to connect under (anonymous)", required = True)
    args = parser.parse_args()
    
    username = args.user
    server = args.server
    print("\x1b[38;2;79;141;255m[i] Connecting...")
    set_loading_anim(True)
    reader, writer = await asyncio.open_connection(server, SERVER_PORT)
    set_loading_anim(False)
    print(f"\x1b[38;2;79;141;255m[*] Connected to {server}:{SERVER_PORT} as {username}")

    await asyncio.gather(send_loop(writer, username), recieve_loop(reader))

def entry():
    asyncio.run(main())

if __name__ == "__main__":
    entry()