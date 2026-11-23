#!/usr/bin/env python3
"""Local rVPN client/server SOCKS5 round-trip regression, with optional Caddy."""

import argparse
import http.server
import ssl
from contextlib import ExitStack, contextmanager
import json
import os
import platform
from pathlib import Path
import secrets
import socket
import socketserver
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


@contextmanager
def open_flow(socks_port, target_port):
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
        yield stream


def roundtrip(socks_port, target_port, nonce):
    start = time.monotonic()
    with open_flow(socks_port, target_port) as stream:
        stream.sendall(nonce)
        if receive(stream, len(nonce)) != nonce[::-1]:
            raise AssertionError("Incorrect response from the echo target")
    return (time.monotonic() - start) * 1000


class LoopbackAddressResolver(socketserver.BaseRequestHandler):
    """The fixture resolves localhost even when HTTPS record discovery fails."""
    def handle(self):
        query, sock = self.request
        name = b"\x09localhost\x00"
        question = query[12:12 + len(name) + 4]
        if not question.startswith(name) or len(question) != len(name) + 4:
            return
        answer = b""
        if question[-4:] == struct.pack("!HH", 1, 1):
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
        sock.sendto(header + question + answer, self.client_address)


def run_case(args, use_caddy, scenario="restart"):
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
             "subjectAltName=DNS:localhost,IP:127.0.0.1", "-out", cert, "-keyout", key],
            check=True, capture_output=True,
        )
        ws_path = "/cw/test-fixture/ws" if args.deployment_link else "/api/v1/ws"
        server_config = {
            "server": {
                "bind_address": f"127.0.0.1:{server_port}",
                "websocket_path": ws_path,
                "tls_cert_file": str(cert) if not use_caddy else str(work / "no-cert.pem"),
                "tls_key_file": str(key) if not use_caddy else str(work / "no-key.pem"),
                "identity_key_file": str(work / "server.key"),
                "prekey_bundle_file": str(work / "bundle.json"),
                # Allow only the isolated loopback echo target.
                "tun": {"enabled": False, "proxy_allow_cidrs": ["127.0.0.2/32"]},
                "logging": {"file_enabled": False},
            }
        }
        (work / "server.json").write_text(json.dumps(server_config))
        server_command = [args.server, "-c", work / "server.json"]
        server = stack.enter_context(launch(server_command, work, "server"))
        wait_port(server_port, server)
        if scenario == "upgrade-rejected":
            server.terminate()
            server.wait(timeout=5)
            class RejectUpgrade(http.server.BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def do_GET(self):
                    self.send_error(403)

                def log_message(self, *args):
                    pass

            fixture = stack.enter_context(http.server.ThreadingHTTPServer(("127.0.0.1", server_port), RejectUpgrade))
            if not use_caddy:
                tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                tls.minimum_version = ssl.TLSVersion.TLSv1_2
                tls.load_cert_chain(cert, key)
                fixture.socket = tls.wrap_socket(fixture.socket, server_side=True)
            threading.Thread(target=fixture.serve_forever, daemon=True).start()
            stack.callback(fixture.shutdown)

        if use_caddy:
            caddyfile = work / "Caddyfile"
            proxy = f"reverse_proxy 127.0.0.1:{server_port}\n"
            if args.deployment_link:
                from install_server import snippet
                proxy = snippet({"path": ws_path, "port": server_port}) + 'handle {\n respond "original site"\n}\n'
            caddyfile.write_text(
                "{\n  admin off\n  auto_https disable_redirects\n}\n"
                f"https://:{public_port} {{\n"
                "  bind 127.0.0.1\n"
                f"  tls {cert} {key}\n"
                f"  {proxy}"
                "}\n"
            )
            caddy = stack.enter_context(launch(
                [args.caddy, "run", "--config", caddyfile, "--adapter", "caddyfile"],
                work, "caddy",
            ))
            wait_port(public_port, caddy)

        client_config = {
            "server_address": f"wss://127.0.0.1:{public_port}{ws_path}",
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
        if scenario.startswith("ech-"):
            client_config["network"] = {"ech_mode": scenario[4:]}
            resolver = stack.enter_context(socketserver.UDPServer(("127.0.0.1", 0), LoopbackAddressResolver))
            threading.Thread(target=resolver.serve_forever, daemon=True).start()
            stack.callback(resolver.shutdown)
            client_config["server_address"] = f"wss://localhost:{public_port}/api/v1/ws"
            client_config["dns_proxy"]["nameservers"] = [
                f"127.0.0.1:{resolver.server_address[1]}", "https://127.0.0.1:9/dns-query",
            ]
        if scenario == "upgrade-rejected":
            client_config["server_address"] += "/invalid"
        (work / "client.json").write_text(json.dumps(client_config))
        if args.deployment_link:
            from install_server import link, upgrade
            address = client_config.pop("server_address")
            client_config.pop("prekey_bundle")
            client_config.pop("sni_hostname")
            (work / "client.json").write_text(json.dumps(client_config))
            public_link = link(address, json.loads((work / "bundle.json").read_text()))
            import_command = [args.client, "-c", work / "client.json", "import", public_link]
            subprocess.run(import_command, check=True, capture_output=True)
            imported = (work / "client.json").read_bytes()
            assert subprocess.run(import_command, capture_output=True).returncode != 0
            assert (work / "client.json").read_bytes() == imported
            if use_caddy:
                from http.client import HTTPSConnection
                for suffix in ("", "/dns", "/tun", "/mux"):
                    upgrade("localhost", public_port, ws_path + suffix, local_tls=True)
                for path in ("/", "/api/config", ws_path, ws_path + "-other"):
                    conn = HTTPSConnection("localhost", public_port, context=ssl.create_default_context(cafile=cert))
                    conn.request("GET", path)
                    assert conn.getresponse().read() == b"original site"
                    conn.close()
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

        if scenario in ("ech-required", "upgrade-rejected"):
            try:
                roundtrip(socks_port, target_port, secrets.token_bytes(32))
            except (OSError, EOFError, AssertionError):
                log = (work / "client.log").read_text()
                if scenario == "ech-required":
                    if "Required ECH" not in log or 'stage="dns_https"' not in log or 'stage="tls_handshake"' in log:
                        raise AssertionError("Missing strict ECH rejection or unexpected TLS fallback")
                elif not any('stage="websocket_upgrade"' in line and "failed" in line and "403" in line
                             for line in log.splitlines()) or 'stage="tls_handshake"' not in log:
                    raise AssertionError("Missing rejection evidence: " + " ".join(line for line in log.splitlines() if "stage=" in line)[-1300:])
                stage = "dns_https" if scenario == "ech-required" else "websocket_upgrade"
                attempts = sum(f'stage="{stage}"' in line and "VPN connection stage failed" in line
                               for line in log.splitlines())
                return {"stage": stage, "retries": max(0, attempts - 1),
                        "tls": "required ECH failed" if scenario == "ech-required" else "ordinary TLS",
                        "roundtrip": False}
            raise AssertionError(f"{scenario} unexpectedly forwarded traffic")

        latencies = [echo_roundtrip() for _ in range(args.samples)]
        with open_flow(socks_port, target_port) as active, listener.accept()[0] as peer:
            active.sendall(b"ping")
            if receive(peer, 4) != b"ping":
                raise AssertionError("Active flow did not reach the origin")
            server.terminate()
            server.wait(timeout=5)
            try:
                if active.recv(1):
                    raise AssertionError("Unexpected bytes after server shutdown")
            except ConnectionResetError:
                pass
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
        if scenario == "ech-prefer" and "ECH unavailable" not in log:
            raise AssertionError("Missing ECH fallback diagnostic")
        full = log.count("session_reused=false")
        resumed = log.count("session_reused=true")
        route = "Caddy" if use_caddy else "direct"
        p95 = statistics.quantiles(latencies, n=100, method="inclusive")[94] if len(latencies) > 1 else latencies[0]
        if args.measure:
            return dict(stage="proxy_first_inbound_data", tls="ordinary TLS fallback" if scenario == "ech-prefer" else "ordinary TLS",
                        roundtrip=True, recovery_ms=round(recovery_ms, 1), latency_ms=round(latencies[0], 1))
        print(f"{route}: {len(latencies)}/{args.samples} round trips, "
              f"first {latencies[0]:.1f} ms, p95 {p95:.1f} ms, "
              f"restart to successful round trip {recovery_ms:.1f} ms, "
              f"TLS handshakes {full} full / {resumed} resumed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--caddy", type=Path, help="also test a local Caddy TLS frontend")
    parser.add_argument("--deployment-link", action="store_true", help="exercise installer routes and real CLI import (Linux)")
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--measure", action="store_true", help="repeat isolated loopback scenarios and report all outcomes as JSON")
    args = parser.parse_args()
    if args.deployment_link and args.measure:
        parser.error("--deployment-link and --measure exercise different scenarios")
    if args.samples < 1:
        parser.error("--samples must be positive")
    for name in ("client", "server", "caddy"):
        path = getattr(args, name)
        if path is not None:
            setattr(args, name, path.resolve(strict=True))
    if args.measure:
        attempts = args.samples
        args.samples = 1
        failures = 0
        for caddy in ([False, True] if args.caddy else [False]):
            for scenario in ("ech-prefer", "ech-required", "upgrade-rejected", "restart"):
                successes = []
                for sample in range(attempts):
                    start = time.monotonic()
                    error = None
                    outcome = {}
                    try:
                        outcome = run_case(args, caddy, scenario)
                    except (OSError, AssertionError, EOFError, RuntimeError, subprocess.SubprocessError) as exc:
                        while exc.__cause__ is not None:
                            exc = exc.__cause__
                        error = str(exc).splitlines()[0] or type(exc).__name__
                    elapsed = round((time.monotonic() - start) * 1000, 1)
                    if error is None:
                        successes.append(elapsed)
                    else:
                        failures += 1
                    print(json.dumps(dict(platform=platform.system(), backend="BoringSSL", route="caddy" if caddy else "direct",
                                          scenario=scenario, sample=sample+1, passed=error is None, error=error, elapsed_ms=elapsed, **outcome)))
                print(json.dumps(dict(route="caddy" if caddy else "direct", scenario=scenario, passed=len(successes), attempted=attempts,
                                      median_success_ms=round(statistics.median(successes), 1) if successes else None)))
        raise SystemExit(bool(failures))
    run_case(args, use_caddy=False)
    if args.caddy:
        run_case(args, use_caddy=True)


if __name__ == "__main__":
    main()
