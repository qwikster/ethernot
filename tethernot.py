import asyncio
import ssl
import os
import datetime
import sys
import ipaddress
import argparse
import shutil
import time
from collections import defaultdict

from cryptography import x509 # i hate myself
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = ".certs" # needs revison, permissions? should be fine. *check on windows, fuck microsoft
SERVER_CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")
SERVER_KEY_FILE = os.path.join(CERT_DIR, "server_key.pem")

clients = set()
blocklist = {}
PORT = 6780

BLOCK_DURATION = 30 # tweak time if it's annoying. client side message? don't think i can b/c no decrypt server side
token_num = 5
token_regen = 1.0
buckets = defaultdict(lambda: TokenBucket(token_num, token_regen))

class TokenBucket:
    __slots__ = ("tokens", "last_ts") # slots?? DID SOMEBODY SAY GAMBLING??
    
    def __init__(self, capacity: float, refill_per_sec: float):
        self.tokens = capacity
        self.last_ts = asyncio.get_event_loop().time()
    
    def consume(self, amount: float = 1.0) -> bool:
        now = asyncio.get_event_loop().time()
        elapsed = max(0.0, now - self.last_ts)
        self.tokens = min(token_num, self.tokens + elapsed * token_regen) # also change these if it's annoying
        self.last_ts = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

def ensure_certificates():
    os.makedirs(CERT_DIR, exist_ok = True)
    
    #generate key+cert if i can't find it
    if not (os.path.exists(SERVER_CERT_FILE) and os.path.exists(SERVER_KEY_FILE)):
        key = rsa.generate_private_key(public_exponent=65537, key_size = 2048) # this server is NOT QUANTUM SAFE (real)
        subject = x509.Name([ # oh god
            x509.NameAttribute(NameOID.COMMON_NAME, u"ethernot-relay"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ethernot"),
        ])
        cert = ( # oh god 2.0
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=120))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650/2))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]), critical=False
                )
            .sign(key, hashes.SHA256())
        )
        
        # write key+cert
        with open(SERVER_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            ))
        with open(SERVER_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
def cert_fp_hex(pem_path):
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.x509 import load_pem_x509_certificate
    with open(pem_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    digest = cert.fingerprint(_hashes.SHA256())
    return digest.hex()
        
async def handle_client(reader, writer):
    ip = writer.get_extra_info('peername') # tuple("ip", "port")
    addr = ip[0] # string, more useful
    now = time.time()
    if addr in blocklist and now < blocklist[addr]:
                print(f"\x1b[38;2;255;80;80m[!] User \x1b[38;2;79;141;255m{addr}\x1b[38;2;255;80;80m is blocked!")
                return
    clients.add(writer)
    print(f"\x1b[38;2;127;255;212m[+] client \x1b[38;2;79;141;255m{addr} \x1b[38;2;127;255;212mconnected")
    
    try:
        while True:
            data = await reader.readline()
            if not data:
                break

            bucket = buckets[addr]

            if not bucket.consume():
                print(f"\x1b[38;2;255;80;80m[!] Client \x1b[38;2;79;141;255m{addr}\x1b[38;2;255;80;80m exceeded rate limit, disconnecting")
                blocklist[addr] = now + BLOCK_DURATION
                break

            broken = []
            
            # broadcast to ALL clients here
            for client in list(clients):
                try:
                    if client is not writer: # did you mean: recursion?
                        client.write(data)
                        await client.drain()
                except Exception:
                    broken.append(client)
            
            for c in broken:
                try:
                    clients.remove(c)
                    broken.remove(c)
                    c.close()
                except Exception:
                    pass
                    
    except (asyncio.IncompleteReadError, ConnectionResetError) as e:
        print(f"\x1b[38;2;255;80;80m[!] error: {e}")
    finally:
        print(f"\x1b[38;2;255;193;79m[-] client \x1b[38;2;79;141;255m{addr}\x1b[38;2;255;193;79m disconnected")
        try:
            clients.remove(writer)
        except KeyError:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
            
async def main():
    global token_num, token_regen, BLOCK_DURATION, PORT
    parser = argparse.ArgumentParser(prog = "tethernot", description = "Server for EtherNOT")
    parser.add_argument("--regencerts", help="Regenerate certificates to connect clients anew.", action = "store_true")
    parser.add_argument("--port", help="Choose a port to run tethernot on. Default: 6780")
    parser.add_argument("--bucket", help="Set the max messages a client can send before being rate limited. Default: 5")
    parser.add_argument("--bucketfill", help="Set the regeneration rate in seconds (float) of the rate limit \"bucket\". Default: 1.0")
    parser.add_argument("--blocktime", help="Set time in seconds to block a user after they've been rate limited. Default: 30")
    args = parser.parse_args()
    
    if args.port: PORT = args.port
    if args.bucket: token_num = args.bucket
    if args.bucketfill: token_regen = args.bucketfill
    if args.blocktime: BLOCK_DURATION = args.blocktime

    if args.regencerts:
        shutil.rmtree(CERT_DIR)
        print("\x1b[38;2;79;141;255m[*] Regenerating certificates!")
    
    ensure_certificates()
    
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    except Exception as e:
        print(f"[i] Something happened: {e}")
        pass
    ssl_ctx.load_cert_chain(certfile=SERVER_CERT_FILE, keyfile = SERVER_KEY_FILE)
    
    try:
        fp = cert_fp_hex(SERVER_CERT_FILE)
        print(f"\x1b[38;2;79;141;255m[*] Server cert SHA256 fingerprint:\n    {fp}")
    except Exception as e:
        print(f"[i] Something happened: {e}")
        pass
    
    server = await asyncio.start_server(handle_client, "0.0.0.0", PORT, ssl=ssl_ctx)
    print(f"\x1b[38;2;79;141;255m[*] tethernot is running on localhost, port {PORT}")
    try:
        async with server:
            await server.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n\n\x1b[38;2;79;141;255m[*] Exiting tethernot")
    finally:
        server.close()
        await server.wait_closed()
    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
