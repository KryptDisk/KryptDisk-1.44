# KryptDisk 1.44

**KryptDisk is an experimental decentralised encrypted-payload utility, exploring alternatives to the trust model of a centralised server and offering a practical protocol for cryptographic time-locking.**

Time-locking is one of the project's central challenges: how can an encrypted
payload be made recoverable only after a future point without relying on a
trusted central clock or server? KryptDisk approaches this by combining
proof-of-work with externally observed blockchain progress, allowing the
network to participate in establishing when a payload may be recovered.

Instead of entrusting an encrypted payload to a central service, KryptDisk moves
it through a peer-to-peer relay mesh. The current beta uses an external
blockchain timing source as a practical reference for elapsed time.

KryptDisk is currently in **public beta**. The software is experimental and
should not be used for critical or irreplaceable data.

## Linux quick start

Requirements: Python 3 with `venv` support and an Internet connection for the
initial Python dependency install and bootstrap connection.

```bash
chmod +x install-linux.sh
./install-linux.sh
```

The setup script creates a local Python virtual environment, installs the Python
requirements, asks for a node name and port, writes `mesh_config.json`, and can
start the node immediately.

If no node name is entered, the default is **Kryptonaut**.

To start an already configured node manually:

```bash
.venv/bin/python launch_node.py "YOUR NODE NAME"
```

## Windows

A packaged Windows 11 beta is provided through GitHub Releases. The installer
preserves an existing KryptDisk configuration during upgrades and will shut
down a running KryptDisk node before replacing application files. The source
tree can also be run directly with a suitable Python environment.

## Network configuration

The distributed `mesh_config.json` contains no pre-created local identity. A
local node entry is created during configuration. The public bootstrap endpoint
is supplied separately under `bootstrap_peers`.

The default beta configuration uses:

- proof-of-work bits: 12
- collision trigger N: 50
- relay enabled for newly configured nodes
- update policy: `stage`
- automatic update apply: off
- automatic update restart: off

## Experimental timing metrics

KryptDisk records local mesh collision activity against externally observed
blockchain progress. The current beta measures collision rate
(`collisions/sec`) at each node and records interval data for later analysis.

Collision rate is an experimental, observer-dependent metric. It is not assumed
to be constant across nodes or equivalent to computational hashrate. The
instrumentation is intended to provide empirical data for investigating whether
distributed mesh activity can contribute a useful measure of elapsed time.

## Local state and identity

KryptDisk creates runtime state beneath its local node directories. Node
identity material, peer state, messages, logs and runtime files are deliberately
excluded from this repository by `.gitignore`.

Successfully decrypted directed payloads are persisted beneath the local
`inbox/` directory, together with limited delivery and retry state. The live
activity/message display is transient and is not intended to provide a
persistent chat history. Users should not treat the current beta interface as
a message archive.

Do not publish or share a live node profile or identity material unless you
specifically intend to transfer custody of that identity.

## Beta status

KryptDisk is under active development. Protocol behaviour, configuration and
update mechanisms may change during beta testing. Inspection, testing and bug
reports are welcome.

## License

KryptDisk is free software licensed under the GNU General Public License
version 3 or later (`GPL-3.0-or-later`).

You may use, study, modify and redistribute KryptDisk under the terms of that
license. See `LICENSE` for details.
