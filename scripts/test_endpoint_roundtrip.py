#!/usr/bin/env python3
"""Local rVPN client/server SOCKS5 round-trip regression, with optional Caddy."""

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import struct
import subprocess
import tempfile
import threading
import time


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def launch(command, cwd, label, env=None):
    log = cwd / f"{label}.log"
    with log.open("wb") as output:
        process = subprocess.Popen(
            command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT
        )
        try:
            yield process
        except Exception as error:
            raise RuntimeError(f"{label} log:\n{log.read_text(errors='replace')}") from error
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def wait_port(port, process):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Listener on loopback port {port} did not start")


def receive(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError("Connection closed before receiving the expected bytes")
        data.extend(chunk)
    return bytes(data)


def roundtrip(socks_port, target_port, nonce):
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", socks_port), timeout=10) as stream:
        stream.sendall(b"\x05\x01\x00")
        if receive(stream, 2) != b"\x05\x00":
            raise AssertionError("SOCKS5 authentication negotiation failed")
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.2") + struct.pack("!H", target_port))
        version, code, _, address_type = receive(stream, 4)
        if (version, code) != (5, 0):
            raise AssertionError(f"SOCKS5 CONNECT returned {code}")
        address_size = {1: 4, 4: 16}.get(address_type)
        if address_type == 3:
            address_size = receive(stream, 1)[0]
        if address_size is None:
            raise AssertionError(f"Unsupported SOCKS5 address type {address_type}")
        receive(stream, address_size + 2)
        stream.sendall(nonce)
        if receive(stream, len(nonce)) != nonce[::-1]:
            raise AssertionError("Incorrect response from the echo target")
    return (time.monotonic() - start) * 1000


def run_case(args, use_caddy):
    with tempfile.TemporaryDirectory(prefix="rvpn-endpoint-") as tmp, ExitStack() as stack:
        work = Path(tmp)
        listener = stack.enter_context(socket.socket())
        # A distinct target avoids the mandatory direct route for the VPN endpoint.
        listener.bind(("127.0.0.2", 0))
        listener.listen()
        listener.settimeout(10)
        target_port = listener.getsockname()[1]
        server_port, socks_port = available_port(), available_port()
        public_port = available_port() if use_caddy else server_port
        cert, key = work / "cert.pem", work / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=localhost", "-addext",
             "subjectAltName=DNS:localhost", "-out", cert, "-keyout", key],
            check=True, capture_output=True,
        )
        server_config = {
            "server": {
                "bind_address": f"127.0.0.1:{server_port}",
                "tls_cert_file": str(cert) if not use_caddy else str(work / "no-cert.pem"),
                "tls_key_file": str(key) if not use_caddy else str(work / "no-key.pem"),
                "identity_key_file": str(work / "server.key"),
                "prekey_bundle_file": str(work / "bundle.json"),
                # The legacy handler already allows targets inside the configured
                # tunnel CIDR. This temporary fixture stays on loopback.
                "tun": {"enabled": False, "tun_ip": "127.0.0.0/24"},
                "logging": {"file_enabled": False},
            }
        }
        (work / "server.json").write_text(json.dumps(server_config))
        server_command = [args.server, "-c", work / "server.json"]
        server = stack.enter_context(launch(server_command, work, "server"))
        wait_port(server_port, server)

        if use_caddy:
            caddyfile = work / "Caddyfile"
            caddyfile.write_text(
                "{\n  admin off\n  auto_https disable_redirects\n}\n"
                f"https://:{public_port} {{\n"
                "  bind 127.0.0.1\n"
                f"  tls {cert} {key}\n"
                f"  reverse_proxy 127.0.0.1:{server_port}\n"
                "}\n"
            )
            caddy = stack.enter_context(launch(
                [args.caddy, "run", "--config", caddyfile, "--adapter", "caddyfile"],
                work, "caddy",
            ))
            wait_port(public_port, caddy)

        client_config = {
            "server_address": f"wss://127.0.0.1:{public_port}/api/v1/ws",
            "sni_hostname": "localhost",
            "identity_key_file": str(work / "client.key"),
            "prekey_bundle": str(work / "bundle.json"),
            "data_dir": str(work / "data"),
            "socks5": {"listen_address": f"127.0.0.1:{socks_port}", "mode": "legacy"},
            "tun": {"enabled": False},
            "dns_proxy": {"enabled": False},
            "http_proxy": {"enabled": False},
            "split_tunnel": {"enabled": False},
            "logging": {"file_enabled": False},
        }
        (work / "client.json").write_text(json.dumps(client_config))
        client = stack.enter_context(launch(
            [args.client, "-v", "-c", work / "client.json"], work, "client",
            {**os.environ, "SSL_CERT_FILE": str(cert)},
        ))
        wait_port(socks_port, client)

        def echo_roundtrip():
            nonce = secrets.token_bytes(32)
            errors = []

            def echo():
                try:
                    stream, _ = listener.accept()
                    with stream:
                        stream.settimeout(10)
                        received = receive(stream, len(nonce))
                        stream.sendall(received[::-1])
                        # Let the SOCKS5 client consume the reply before EOF.
                        if stream.recv(1):
                            raise AssertionError("Unexpected data after the echo request")
                except (OSError, EOFError, AssertionError) as error:
                    errors.append(error)

            target = threading.Thread(target=echo, daemon=True)
            target.start()
            latency = roundtrip(socks_port, target_port, nonce)
            target.join(timeout=1)
            if target.is_alive() or errors:
                raise AssertionError(f"Echo target did not complete: {errors}")
            return latency

        latencies = [echo_roundtrip() for _ in range(args.samples)]
        server.terminate()
        server.wait(timeout=5)
        try:
            roundtrip(socks_port, target_port, secrets.token_bytes(32))
        except (OSError, EOFError, AssertionError):
            pass
        else:
            raise AssertionError("Round trip unexpectedly succeeded with the VPN server stopped")
        recovery_started = time.monotonic()
        server = stack.enter_context(launch(server_command, work, "server-restart"))
        wait_port(server_port, server)
        echo_roundtrip()
        recovery_ms = (time.monotonic() - recovery_started) * 1000
        log = (work / "client.log").read_text()
        for stage in ("dns_address", "tcp_connect", "tls_handshake", "websocket_upgrade",
                      "x3dh_handshake", "proxy_first_inbound_data"):
            if f'stage="{stage}"' not in log:
                raise AssertionError(f"Missing client diagnostic for {stage}")
        full = log.count("session_reused=false")
        resumed = log.count("session_reused=true")
        route = "Caddy" if use_caddy else "direct"
        p95 = statistics.quantiles(latencies, n=100, method="inclusive")[94] if len(latencies) > 1 else latencies[0]
        print(f"{route}: {len(latencies)}/{args.samples} round trips, "
              f"first {latencies[0]:.1f} ms, p95 {p95:.1f} ms, "
              f"restart to successful round trip {recovery_ms:.1f} ms, "
              f"TLS handshakes {full} full / {resumed} resumed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--caddy", type=Path, help="also test a local Caddy TLS frontend")
    parser.add_argument("--samples", type=int, default=10)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("--samples must be positive")
    for name in ("client", "server", "caddy"):
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, path.resolve(strict=True))
    run_case(args, use_caddy=False)
    if args.caddy:
        run_case(args, use_caddy=True)


if __name__ == "__main__":
    main()
