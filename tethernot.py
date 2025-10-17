import asyncio
import ssl
import os
import datetime
import sys
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_DIR = ".certs"
CA_CERT_FILE = os.path.join(CERT_DIR, "ca_cert.pem") # should (?) never be needed by client
SERVER_CERT_FILE = os.path.join(CERT_DIR, "server_cert.pem")
SERVER_KEY_FILE = os.path.join(CERT_DIR, "server_key.pem")

clients = set()
PORT = 6780

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
                x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
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
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import load_pem_x509_certificate
    with open(pem_path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    digest = cert.fingerprint(hashes.SHA256())
    return digest.hex()
        
async def handle_client(reader, writer):
    clients.add(writer)
    broken_clients = []
    addr = writer.get_extra_info('peername')
    print(f"\x1b[38;2;127;255;212m[+] client {addr} connected")
    
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            # broadcast to ALL clients here
            for client in list(clients):
                try:
                    if client is not writer: # did you mean: recursion?
                        client.write(data)
                        await client.drain()
                except Exception:
                    broken_clients.appent(client)
            
            for c in broken_clients:
                try:
                    clients.remove(c)
                    c.close()
                except Exception:
                    pass
                    
    except (asyncio.IncompleteReadError, ConnectionResetError) as e:
        print(f"\x1b[38;2;255;80;80m[!] error: {e}")
    finally:
        print(f"\x1b[38;2;255;193;79m[-] client {addr} disconnected")
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
        print(f"\x1b[38;2;79;141;255m[*] Server cert SHA256 fingerprint: \n{fp}")
    except Exception as e:
        print(f"[i] Something happened: {e}")
        pass
    
    server = await asyncio.start_server(handle_client, "0.0.0.0", PORT, ssl=ssl_ctx)
    print(f"\x1b[38;2;79;141;255m[*] tethernot is running on localhost, port {PORT}")
    async with server:
        await server.serve_forever()
    
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n\x1b[38;2;79;141;255m[*] Exiting tethernot")
        sys.exit(0)
