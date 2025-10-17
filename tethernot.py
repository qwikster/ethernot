import asyncio

clients = set()

async def handle_client(reader, writer):
    clients.add(writer)
    addr = writer.get_extra_info('peername')
    print(f"\x1b[38;2;127;255;212m[+] client {addr} connected")
    
    try:
        while data := await reader.readline():
            # broadcast to ALL clients here
            for client in clients:
                if client is not writer: # did you mean: recursion?
                    client.write(data)
                    await client.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError) as e:
        print(f"\x1b[38;2;255;80;80m[!] error: {e}")
    finally:
        print(f"\x1b[38;2;255;193;79m[-] client {addr} disconnected")
        clients.remove(writer)
        writer.close()
        await writer.wait_closed()
        
async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 6780)
    print("\x1b[38;2;79;141;255m[*] tethernot is running on localhost, port 6780")
    async with server:
        await server.serve_forever()
    
if __name__ == "__main__":
    asyncio.run(main())


