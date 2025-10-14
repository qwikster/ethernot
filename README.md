# ethernot
Super-simple encrypted command line text messaging where messages are stored only in the memory of all computers connected.
> pronounced like "ethernet" but... not

## installation
`pip install ethernot` (or pipx if you so require)

## usage
`ethernot --server <server>`
There is a test server hosted at `PLACEHOLDER`, or you may host your own instance of tethernot by zcrolling down.

## features
- Runs on any device that supports Python and is connected to the internet.
- No port forwarding necesary, unless you're hosting a relay server.
- Server never saves any messages - not even in memory. It can't even read them.
- Your messages are never saved to disk. They're only kept alive by any clients connected - all clinets have their memory synchronized.
- No stupid accounts or dependencies needed. All messages are only linked to whichever username you choose for the session.
- Multiple channel support
- Minimal command line interface. Server doesn't even need to output anything.
- No analytics, trackers, or bigwig corporate executives spying on your every move.