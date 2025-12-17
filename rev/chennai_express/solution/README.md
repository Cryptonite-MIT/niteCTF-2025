# Chennai Express

**Flag**: `nite{T#r0ugh_g0e5_Th0m4s!!}`

[Visualisation script](client.py)

This is a .NET binary with a train simulation, consisting of switches. Communication over `nc` is done in the following format:

- Packet: `<length><json-encoded (packet type + information)>`
- Information: json-encoded

The player can send packets to request the game state and update switch state. There is a class which checks the state of all switches upon receiving a request, only switching the state if the checks pass.
- Only one green switch at a time
- Switch can only become green if the destination track is not occupied.

All switches have a delay, before they check and switch, with a single exception. There is a switch (ID -1) which has a delay between the checking and switching, making this a TOCTOU (Time of Check - Time of Use) exploit. Activating a normal switch, then immediately activiating Switch `-1` will make both switches green. This is what will make the trains crash.

[The solve script](solve.py) does the following:

- Send `B` to Track 1 using Switch `-3`
- Send `A` to Track 3 using Switch `6`
- Send `B` to Track 2 using Switch `2`
- Activate Switch `-3`, immediately activate Switch `-1` without delay. Now, both Switches are green and the trains crash in Track 1 (due to the speed difference)
