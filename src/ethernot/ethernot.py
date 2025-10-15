import argparse
import threading
import sys
import time
import random

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
        

def connect(server, user):
    print(f"Connecting to {server} as {user}...")
    set_loading_anim(True)
    time.sleep(5)
    set_loading_anim(False)
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(prog="ethernot", description="EtherNOT CLI Client")
    parser.add_argument("--server", help="Server IP to connect to", required = True)
    parser.add_argument("--user", help="Username to connect under (anonymous)", required = True)
    args = parser.parse_args()
    
    connect(args.server, args.user)


if __name__ == "__main__":
    main()