import argparse
import threading
import time
import random
import asyncio
import json
import signal
import sys
import re
import ssl
import os
import hashlib
from pathlib import Path
from collections import defaultdict, deque

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import FormattedText

SERVER_PORT = 6780
MAX_MESSAGE_BYTES = 8192
MAX_BODY_CHARS = 4096
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

FINGERPRINT_FILE = os.path.join(Path.home(), ".ethernot_server_fingerprint")

_animation_event = threading.Event()
_animation_thread = None

users = []
shutdown_event = asyncio.Event()
channel = "general"
channel_list = ["general"]
local_username = None
histories = defaultdict(lambda: deque(maxlen=100))

def compute_cert_fingerprint_from_sslobj(sslobj):
    if sslobj is None:
        return None
    der = None
    try:
        der = sslobj.getpeercert(binary_form=True)
    except Exception as e:
        print(f"[!] Something happened: {e}")
        return None
    if not der:
        return None
    h = hashlib.sha256(der).hexdigest()
    return h

def save_pinned_fingerprint(fp_hex):
    try:
        with open(FINGERPRINT_FILE, "w") as f:
            f.write(fp_hex.strip().lower())
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print_formatted_text(FormattedText([("fg:#FF4444", f"[!] Failed to write fingerprint: {e}")]))

def load_pinned_fingerprint():
    try:
        if os.path.exists(FINGERPRINT_FILE):
            with open(FINGERPRINT_FILE, "r") as f:
                return f.read().strip().lower()
    except Exception as e:
        print_formatted_text(FormattedText([("fg:#FF4444", f"[!] Error whilst loading fingerprint: {e}")]))
    return None

def make_ssl_context_for_client():
    # intentionally allow handshake without CA verification
    # doing manual fingerprint pinning for this since anonynymasfsdgjity is important
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception:
        pass
    return ctx

def little_bobby_tables(s: str, maxlen: int = MAX_BODY_CHARS) -> str:
    # for the uninitiated: message sanitizer, remove control chars
    # https://xkcd.com/327/
    if not isinstance(s, str):
        s = str(s)
    s = re.sub(r'[\x00-\x1f\x7f]+', ' ', s)
    if len(s) > maxlen:
        s = s[:maxlen]
    return s

def validate_regex(inp: str, regex) -> bool:
    if not isinstance(inp, str):
        return False
    return bool(regex.match(inp))
    
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
        print("\r", end="", flush=True)
        print()

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
        ("fg:#51DBBB", "[/who] > "),
        ("", "List currently online users\n"),
    ]))

def list_users():
    if not users:
        userlist_text = FormattedText([("fg:#884444", "You're all alone...")])
    else:
        joined = ", ".join(users)
        userlist_text = FormattedText([("", joined)])
    print_formatted_text(FormattedText([
        ("fg:#FFC600", "[ethernot/who]\n"),
        ("fg:#51DBBB", f"Currently {len(users)} clients connected. Active:"),
    ]))
    print_formatted_text(userlist_text)

async def send_msg(writer, msg):
    try:
        encoded = (json.dumps(msg) + "\n").encode()
    except Exception as e:
        print_formatted_text(FormattedText([
            ("fg:#FF4444", f"[!] JSON encode error: {e}")
        ]))
        return False
    
    if len(encoded) > MAX_MESSAGE_BYTES:
        print_formatted_text(FormattedText([
            ("fg:#FF4444", f"[!] Length of parcel ({len(encoded)} chars) is above the message limit of 4096")
        ]))
        return False
    
    try:
        writer.write(encoded)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        print_formatted_text(FormattedText([("fg:#FF4444", "[!] Connection lost.")]))
        shutdown_event.set()
        return False
    except Exception as e:
        print_formatted_text(FormattedText([("fg:#FF4444", f"[!] Unexpected error while sending: {e}")]))
        shutdown_event.set()
        return False
    return True

async def send_loop(writer, username, session):
    color = "#9966FF"
    global channel
    global channel_list
    global local_username
    local_username = username
    first_time = True
    
    try:
        while not shutdown_event.is_set():
            if first_time:
                first_time = False
                msg = { # Send join packet, notify other users you're here
                    "type": "join",
                    "author": username,
                    "channel": channel
                }
                status = await send_msg(writer, msg)
                if not status:
                    break
                who_req = { # Request packets from other users for usernames
                    "type": "who_request",
                    "author": username
                }
                status = await send_msg(writer, who_req)
                if not status:
                    break
                hist_req = { # Get history from other channels from one specific user
                    "type": "history_request",
                    "author": username,
                    "channel": channel,
                    "target": username # non anonymous? maybe have it pick one at random
                }
                await send_msg(writer, hist_req)
                continue
            
            prompt_text = FormattedText([(f"fg:{color}", f"[{username}]"), ("", " >> ")])
            try:
                line = await session.prompt_async(prompt_text)
            except (KeyboardInterrupt, EOFError, asyncio.CancelledError):
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
            
            elif line.startswith("/name") or line.startswith("/nick"):
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    print_formatted_text(FormattedText([("fg:#FF4444", "[!] Usage: /nick <username>")]))
                    continue
                new_name = parts[1].strip()
                if validate_regex(new_name, USERNAME_RE):
                    local_username = new_name
                    username = new_name
                    if username not in users:
                        users.append(username)
                    print_formatted_text(FormattedText([
                       (f"fg:{color}", f"[✓] Username set to {username}") 
                    ]))
                else:
                    print_formatted_text(FormattedText([
                        ("fg:#FF4444", f"[!] Invalid username: {new_name}. Max 32 chars, alphanumeric plus _.-")
                    ]))
                continue
            
            elif line.startswith("/color"):
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    print_formatted_text(FormattedText([("fg:#FF4444", "[!] Usage: /color #RRGGBB")]))
                    continue
                if validate_regex(parts[1].strip(), COLOR_RE):
                    color = parts[1].strip()
                    print_formatted_text(FormattedText([
                       (f"fg:{color}", f"[✓] Color set to {color}") 
                    ]))
                else:
                    print_formatted_text(FormattedText([
                        ("fg:#FF4444", f"[!] Invalid hex color: {parts[1].strip()}.")
                    ]))
                continue
            
            elif line.startswith("/create"):
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    print_formatted_text(FormattedText([("fg:#FF4444", "[!] Usage: /create <channel>")]))
                    continue
                if validate_regex(parts[1].strip(), USERNAME_RE):
                    channel = parts[1].strip()
                    channel_list.append(channel)
                    msg = {
                        "type": "newchannel",
                        "name": channel,
                        "author": username,
                    }
                    status = await send_msg(writer, msg)
                    if not status:
                        break
                    print_formatted_text(FormattedText([
                        ("fg:#51DBBB", f"[i] Created channel ethernot/{parts[1].strip()}."),
                    ]))
                    continue
                else:
                    print_formatted_text(FormattedText([
                        ("fg:#FF4444", f"[!] Invalid channel name: {parts[1].strip()}.")
                    ]))
                    
            elif line == "/list":
                channellist = "], [ethernot/".join(channel_list)
                the = ("[ethernot/" + channellist + "]")
                print(the)
                continue
            
            elif line.startswith("/join") or line.startswith("/switch"):
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    print_formatted_text(FormattedText([("fg:#FF4444", "[!] Usage: /join <channel>")]))
                    continue
                if parts[1].strip() in channel_list:
                    channel = parts[1].strip()
                    print_formatted_text(FormattedText([
                        ("fg:#51DBBB", f"[i] Moved to ethernot/{parts[1].strip()}"),
                    ]))
                    hist_req = {
                        "type": "history_request",
                        "author": username,
                        "channel": channel,
                        "target": username
                    }
                    await send_msg(writer, hist_req)
                else:
                    print_formatted_text(FormattedText([
                        ("fg:#FF4444", f"[!] Channel doesn't appear to exist: {parts[1].strip()}.")
                    ]))
                continue
            
            body = little_bobby_tables(line)
            msg = { # expand this
                "type": "message",
                "channel": channel,
                "author": username,
                "color": color,
                "timestamp": time.time(),
                "body": body
            }
            
            try:
                histories[channel].append({
                    "timestamp": msg["timestamp"],
                    "author": msg["author"],
                    "color": msg["color"],
                    "body": msg["body"]
                })
            except Exception:
                pass
            
            status = await send_msg(writer, msg)
            if not status:
                break
            elif status:
                continue
                
    except asyncio.CancelledError:
        return
    except Exception as e:
        print_formatted_text(FormattedText([
            ("fg:#FF4444", f"[!] issue sending: {e} (You should never see this! Report to @qwik)")
        ]))
        shutdown_event.set()
    finally:
        try:
            msg = {
                "type": "leave",
                "author": username
            }
            await send_msg(writer, msg)
        except Exception:
            pass
        print_formatted_text(FormattedText([    
            ("fg:#888888", "[*] Exiting ethernot. goodbye :)")
        ]))
        
async def recieve_loop(reader):
    global channel
    global channel_list
    global local_username
    
    try:
        while not shutdown_event.is_set():
            try:
                data = await reader.readline()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print_formatted_text(FormattedText([("fg:#FF4444", f"[!] Unexpected error reading from server: {e}")]))
                shutdown_event.set()
                break
            
            if not data:
                shutdown_event.set()
                break
            
            if len(data) > MAX_MESSAGE_BYTES:
                print_formatted_text(FormattedText([("fg:#FF4444", "[!] Server sent an oversized message: dropping to avoid issues. There may be a modified or outdated client connected.")]))
                shutdown_event.set()
                break
                
            try:
                msg = json.loads(data.decode(errors="replace"))
                if not isinstance(msg, dict):
                    raise ValueError("Message is not an object! (Corrupted or still encrypted?)")
                msgtype = msg.get("type", "?")
                
                def safe_author(m):
                    return little_bobby_tables(m.get("author", "?"), maxlen = 32)
                
                if msgtype == "message":
                    ch = msg.get("channel", "?")
                    author = safe_author(msg)
                    if author not in users:
                        users.append(author)
                    color = msg.get("color", "#9966FF")
                    if not validate_regex(color, COLOR_RE):
                        color = "#9966FF"
                    body = little_bobby_tables(msg.get("body", ""))
                    
                    try:
                        histories[ch].append({
                            "timestamp": msg.get("timestamp", time.time()),
                            "author": author,
                            "color": color,
                            "body": body
                        })
                    except Exception:
                        pass
                    
                    if ch == channel:
                        print_formatted_text(FormattedText([
                            (f"fg:{color}", f"[{author}]"),
                            ("", f" >> {body}")
                        ]))
                        
                elif msgtype == "newchannel":
                    name = msg.get("name")
                    if name and name not in channel_list:
                        channel_list.append(name)
                    author = safe_author(msg)
                    if author not in users:
                        users.append(author)    
                    print_formatted_text(FormattedText([
                        ("fg:#51DBBB", f"[i] {msg.get("author", "?")} created the channel ethernot/{msg.get("name", "?")}!"),
                    ]))
                    
                elif msgtype == "join":
                    author = safe_author(msg)
                    ch = msg.get("channel")
                    if author not in users:
                        users.append(author)
                    if ch and ch not in channel_list:
                        channel_list.append(ch)
                    print_formatted_text(FormattedText([
                        ("fg:#51DBBB", f"[+] {msg.get("author", "?")} connected"),
                    ]))
                    
                elif msgtype == "leave":
                    author = msg.get("author") or "?"
                    try:
                        if author in users:
                            users.remove(author)
                    except ValueError:
                        pass  # already gone

                    print_formatted_text(FormattedText([
                        ("fg:#ffc14f", f"[-] {author} left")
                    ]))
                    
                elif msgtype == "who_request":
                    requester = msg.get("author")
                    resp = {
                        "type": "who_response",
                        "author": local_username,
                        "channel": channel,
                        "channels": channel_list,
                        "target": requester
                    }
                    if local_username and local_username not in users:
                        users.append(local_username)
                        
                    outgoing_responses.append(resp) # recieve loop can't directly send messages so we set up another writer loop and a queue
                    pass
                    
                elif msgtype == "history_request":
                    req_channel = msg.get("channel")
                    requester = msg.get("author")
                    msgs = list(histories.get(req_channel, []))
                    hist_resp = { # hopefully send a channel-specific packet, need to remove byte limit on this one!!!
                        "type": "history_response",
                        "author": local_username,
                        "channel": req_channel,
                        "messages": msgs,
                        "target": requester
                    }
                    outgoing_responses.append(hist_resp)
                
                elif msgtype == "history_response":
                    target = msg.get("target")
                    resp_channel = msg.get("channel")
                    messages = msg.get("messages", [])
                    if resp_channel and resp_channel not in channel_list:
                        channel_list.append(resp_channel)
                    try:
                        for m in messages:
                            histories[resp_channel].append({
                                "timestamp": m.get("timestamp", time.time()),
                                "author": m.get("author", "?"),
                                "color": m.get("color", "#9966FF"),
                                "body": m.get("body", "")
                            })
                    except Exception:
                        pass
                    if target == local_username and resp_channel == channel:
                        for m in list(histories[resp_channel]):
                            author = m.get("author", "?")
                            body = m.get("body", "")
                            color = m.get("color", "#9966FF")
                            print_formatted_text(FormattedText([
                                (f"fg:{color}", f"[{author}]"),
                                ("", f" >> {body}")
                            ]))
                else:
                    print(msgtype, "< Unknown message type, outdated client?")
                    
            except json.JSONDecodeError as e:
                print_formatted_text(FormattedText(["fg:#FF4444", f"[!] malformed message: {e}"]))
            except Exception as e:
                print_formatted_text(FormattedText(["fg:#FF4444", f"[!] error processing message: {e}"]))

    except asyncio.CancelledError:
        return

def handle_sigint():
    if not shutdown_event.is_set():
        shutdown_event.set()

outgoing_responses = []

async def main():
    parser = argparse.ArgumentParser(prog="ethernot", description="EtherNOT CLI Client")
    parser.add_argument("--server", help="Server IP to connect to", required = True)
    parser.add_argument("--user", help="Username to connect under (anonymous)", required = True)
    parser.add_argument("--renew", help="Get a new fingerprint from the server", action="store_true")
    args = parser.parse_args()
    
    if args.renew:
        try:
            if os.path.exists(FINGERPRINT_FILE):
                os.remove(FINGERPRINT_FILE)
                print("\x1b[38;2;79;141;255m[*] Regenerating certificates!")
        except Exception:
            pass
    
    username = args.user.strip()
    if not validate_regex(username, USERNAME_RE):
        print("\x1b[38;2;255;80;80m[!] Invalid username: 1-32 chars: alphanumeric plus _.-")
        return
    
    if username not in users:
        users.append(username)
        
    server = args.server.strip()
    
    print("\x1b[38;2;79;141;255m[i] Connecting...")
    set_loading_anim(True)
    
    ssl_ctx = make_ssl_context_for_client()
    try:
        reader, writer = await asyncio.open_connection(server, SERVER_PORT, ssl=ssl_ctx)
    except Exception as e:
        set_loading_anim(False)
        print(f"\x1b[38;2;255;80;80m[!] Connection to {server}:{SERVER_PORT} failed: {e}")
        return
    
    try: #handshake worked, get the fingerprint (MITM risk here but should be ok)
        transport = writer.transport
        sslobj = transport.get_extra_info('ssl_object')
        fp = compute_cert_fingerprint_from_sslobj(sslobj)
        if not fp:
            raise RuntimeError("Couldn't read cert fingerprint!")
    except Exception as e:
        set_loading_anim(False)
        print(f"\x1b[38;2;255;80;80m[!] Failed to get server cert: {e}")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return
            
    pinned = load_pinned_fingerprint()
    if pinned is None:
        save_pinned_fingerprint(fp)
        print(f"\n\x1b[38;2;79;141;255m[*] Pinned server fingerprint: {fp}")
    elif pinned != fp:
        set_loading_anim(False)
        print("\x1b[38;2;255;80;80m[!] Server fingerprint does not match pinned fingerprint! Aborting - use --renew to get a new copy of the fingerprint if the server has restarted.")
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return
                
    set_loading_anim(False)
    print(f"\x1b[38;2;79;141;255m[*] Connected to {server}:{SERVER_PORT} as {username}")

    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except NotImplementedError:
        print("\x1b[38;2;255;80;80m[!] something here is broken on windows, tell @qwik")
        pass

    session = PromptSession()
    
    async def send_loop_with_outbox(writer, username, session):
        try:
            while not shutdown_event.is_set():
                if outgoing_responses:
                    resp = outgoing_responses.pop(0)
                    if not resp.get("author"):
                        resp["author"] = local_username or username
                    await send_msg(writer, resp)
                    await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(0.1) # delay will add latency but prevent spinning while loop, oh well
        except asyncio.CancelledError:
            pass
    
    with patch_stdout():
        recv_task = asyncio.create_task(recieve_loop(reader))
        send_task = asyncio.create_task(send_loop(writer, username, session))
        out_send_task = asyncio.create_task(send_loop_with_outbox(writer, username, session))

        await shutdown_event.wait()
        for t in (send_task, recv_task, out_send_task):
            if not t.done():
                t.cancel()
        await asyncio.gather(send_task, recv_task, out_send_task, return_exceptions=True)

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