# ethernot
Super-simple encrypted command line text messaging where messages are stored only in the memory of all computers connected.
> pronounced like "ethernet" but... not

## installation
`pip install ethernot` (or pipx if you so require)

## usage
`ethernot --server <server> --user <username>`
If the server requires, you may `--renewcerts`
There is a test server hosted at `70.27.0.129`, or you may host your own instance of tethernot by scrolling down.

## features
- Runs on any device that supports Python and is connected to the internet.
- No port forwarding necessary, unless you're hosting a relay server.
- Server never saves any messages - not even in memory. It can't even read them.
- Your messages are never saved to disk. They're only kept alive by any clients connected.
- No stupid accounts needed. All messages are only linked to whichever username you choose for the session.
- Multiple channel support.
- Minimal command line interface. Server doesn't even need to output anything (but it still does).
- No analytics, trackers, or bigwig corporate executives spying on your every move.
- Per-IP rate limiting and basic sync - no banning though, that just wouldn't work.
- Kinda-sorta-encrypted? idk encryption is hard
<br>
NOTE: Traffic is encrypted, but ethernot is !VULNERABLE! to man-in-the-middle attacks during a client's *first* connection.

## hosting
To host your own tethernot server:
- Install tethernot's dependencies: `asyncio`, `cryptography`
- Port forward port `6780` on your router. This will vary based on your manufacturer; if you can't figure out how to do it, you shouldn't be messing with it.
- NOTE: If your network is behind CG-NAT, you will not be able to port forward and thus will not be able to run tethernot. The client will still run fine!
- Clone the repository: `git clone https://github.com/qwikster/ethernot.git`
- Move into it: `cd /ethernot`
- Start the `tethernot.py` script: `python tethernot.py`
- That's it! Share the ip with your users and they can connect. You can't do anything but see IP addresses on this client, it's just a relay.
- If you ever need to regenerate the server certificates: `python tethernot.py --regencerts`

# arguments
Some useful arguments for `tethernot`:
| Argument | Use | Default Value |
| ----- | ----- | ----- |
| --regencerts | Regenerate certificates to connect clients anew. | -- | 
| --port <0-65536> | Choose a port to run tethernot on. | 6780 |
| --bucket <num> | Set the max messages a client can send before being rate limited. | 5 messages |
| --bucketfill <secs> | Set the regeneration rate in seconds (float) of the rate limit "bucket". | 1.0 seconds |
| --blocktime <secs> | Set time in seconds to block a user after they've been rate limited. | 30 seconds |
