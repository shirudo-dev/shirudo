# ksock-dummy

Send `shirudo ksock dummy\n` once per load to `10.0.2.2:19090`, the
QEMU host, using the BPF ksock create, connect, send and release kfuncs.
The kernel needs those kfuncs and `CONFIG_INET=y`.

The program runs in the loading task's network namespace, attaches no
hooks and releases its socket on every path. It shares no mutable state
and supports every preemption model. Socket errors fail the load; UDP
send success does not prove delivery or authenticate the receiver.
Boot restore sends again and needs an initrd route to the destination.

Start a receiver on the host before loading:

```sh
python3 - <<'PYTHON'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1", 19090))
    data, peer = server.recvfrom(65535)
    assert data == b"shirudo ksock dummy\n", (peer, data)
    print(data)
PYTHON
```

Build and sign on the operator using an existing keypair:

```sh
shirudo build upatches/ksock-dummy/ksock-dummy.bpf.c \
    --name ksock-dummy -o ksock-dummy.upatch --keys-dir ./keys
payload=$(shirudo upatch info ksock-dummy.upatch --json |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])')
shirudo build --unload ksock-dummy --payload-sha256 "$payload" \
    -o ksock-dummy.unload.upatch --keys-dir ./keys
```

Override `DEST_ADDR` (host-order IPv4 integer) and `DEST_PORT` with
`--extra-cflags` before signing, then rebuild the matching unload.
`shirudo bpm build upatches/ksock-dummy --version 1.0.0 --keys-dir ./keys`
builds the package with its unload directive and this README.

Copy both artifacts to an initialized target that trusts the signer:

```sh
shirudo upatch load ksock-dummy.upatch
shirudo upatch unload ksock-dummy.unload.upatch
```

Run the end-to-end test:

```sh
sudo make -C testing end2end
```

The test loads and unloads signed fixtures and checks the exact datagram
on the host. It needs KVM and the normal VM prerequisites, including Docker.
