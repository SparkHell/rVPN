"""Interactive systemd deployment for Debian and Ubuntu."""
import argparse
import caddy_ech
import base64
import fcntl
import fnmatch
import glob
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ETC = Path("/etc/rvpn")
STATE = ETC / "installation.json"
CADDY = Path("/etc/caddy/Caddyfile")
UNITS = Path("/etc/systemd/system")
BIN = Path("/usr/local/bin")
DATA = Path("/var/lib/rvpn-server")
MIRROR = Path("/var/lib/rvpn-mirrorproxy")
SUFFIXES = ("", "/mux", "/dns", "/tun")
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
WS_PATH = re.compile(r"(?:/[A-Za-z0-9_-]+)+")
PUBLIC_KEYS = ("identity_key", "identity_x25519_key", "signed_prekey", "prekey_signature",
               "one_time_prekey", "identity_key_version", "rotation_signature")


def run(*args, capture=False, cwd=None):
    return subprocess.run(args, check=True, text=True, cwd=cwd, stdout=subprocess.PIPE if capture else None).stdout


def yes(prompt, default=True):
    answer = input(prompt + (" [Y/n] " if default else " [y/N] ")).strip().lower()
    return default if not answer else answer in ("y", "yes")


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        try:
            if path.exists():
                stat = path.stat()
                os.fchown(out.fileno(), stat.st_uid, stat.st_gid)
            os.fchmod(out.fileno(), mode)
            out.write(content.encode())
            out.flush()
            os.fsync(out.fileno())
            os.replace(out.name, path)
        finally:
            Path(out.name).unlink(missing_ok=True)


def link(address, bundle):
    public = {k: bundle[k] for k in PUBLIC_KEYS if k in bundle}
    for key in PUBLIC_KEYS[:4]:
        if key not in public:
            raise ValueError(f"公开预密钥包缺少 {key}")
    body = json.dumps(dict(v=1, address=address, bundle=public), separators=(",", ":")).encode()
    return "rVPN://" + base64.urlsafe_b64encode(body).rstrip(b"=").decode()


def show_link(state):
    print(link(f"wss://{state['domain']}{state['path']}", json.loads((DATA / "prekey-bundle.json").read_text())))


def caddy_service_config():
    unit = run("systemctl", "show", "caddy", "-p", "ExecStart", "--value", capture=True)
    argv = re.search(r"argv\[\]=(.*?) ;", unit)
    if argv:
        words = shlex.split(argv[1])
        if "--config" in words and "--resume" not in words:
            index = words.index("--config") + 1
            if index < len(words):
                path = Path(words[index])
                if path.is_absolute() and path.is_file() and path.suffix.lower() != ".json":
                    return path
    raise ValueError("无法定位 caddy.service 使用的 Caddyfile。请检查 systemctl cat caddy 的 ExecStart。")


def has_unit(name):
    return subprocess.run(["systemctl", "cat", name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def caddy_command(*args, capture=False):
    if caddy_ech.DROPIN.exists():
        if args[0] == "validate":
            credentials = dict(line.split("=", 1) for line in caddy_ech.ENV.read_text().splitlines())
            return caddy_ech.validate(caddy_ech.BINARY, CADDY, credentials)
        return run(str(caddy_ech.BINARY), *args, capture=capture)
    return run("caddy", *args, capture=capture)


def adapted():
    if not CADDY.exists():
        return {}
    return json.loads(caddy_command("adapt", "--adapter", "caddyfile", "--config", str(CADDY), capture=True))


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def host_routes(config, domain):
    return [obj for obj in objects(config)
            if any(fnmatch.fnmatchcase(domain, host) for m in obj.get("match", [])
                   for host in m.get("host", []))]


def source_files(path, visited):
    path = path.resolve()
    if path in visited or not path.is_file():
        return
    visited.add(path)
    yield path
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'\s*import\s+("[^"]+"|[^\s#]+)(?:\s+[^#]*)?\s*(?:#.*)?', line)
        if match:
            pattern = match[1].strip('"')
            for item in glob.glob(str(path.parent / pattern)):
                yield from source_files(Path(item), visited)


def site_location(config, domain):
    if not host_routes(config, domain):
        return None
    matches = []
    plain_http = []
    for path in source_files(CADDY, set()):
        for index, line in enumerate(path.read_text().splitlines(True)):
            header = re.fullmatch(r'\s*(?:(https?)://)?([\w.-]+)(?::(80|443))?\s*\{\s*(?:#.*)?', line.rstrip())
            if header and header[2].lower() == domain:
                candidates = plain_http if header[1] == "http" or header[3] == "80" else matches
                candidates.append((path, index + 1))
    matches = matches or plain_http
    if len(matches) != 1:
        raise ValueError(f"{domain} 匹配现有站点，但不能唯一定位独立域名配置块。请明确站点声明后重试。")
    return matches[0]


def conflict(config, domain, base):
    for site in host_routes(config, domain):
        for obj in objects(site):
            for pattern in obj.get("path", []) if isinstance(obj.get("path"), list) else ():
                if pattern not in ("*", "/*") and any(fnmatch.fnmatchcase((base + s).lower(), pattern.lower()) for s in SUFFIXES):
                    return pattern
    return None


def site_probe(domain, base):
    # Direct-to-local TLS with the actual Host/SNI; existing locally issued
    # certificates need not be trusted for a route-presence check.
    for suffix in SUFFIXES:
        conn = http.client.HTTPSConnection(domain, timeout=3, context=ssl._create_unverified_context())
        conn._create_connection = lambda _, timeout, *args: socket.create_connection(("127.0.0.1", 443), timeout)
        try:
            conn.request("GET", base + suffix)
            status = conn.getresponse().status
            if status != 404:
                return f"{base + suffix} 返回 HTTP {status}"
        except OSError as error:
            return str(error)
        finally:
            conn.close()
    return None


def choose_path(config, domain, existing):
    while True:
        value = input("WebSocket 路径 [/cw/ws]，输入 r 随机生成：").strip() or "/cw/ws"
        for _ in range(32):
            path = f"/cw/{secrets.token_hex(8)}/ws" if value == "r" else value
            if not WS_PATH.fullmatch(path) or len(path) > 200:
                print("路径须由字母、数字、下划线、短横线和 / 组成")
                break
            pattern = conflict(config, domain, path)
            if pattern:
                if value == "r":
                    continue
                print(f"路径冲突：已有规则 {pattern}。请改选路径，可输入 r。")
                break
            occupied = None
            if existing:
                for suffix in SUFFIXES:
                    try:
                        upgrade(domain, 443, path + suffix, local_tls=True)
                    except (OSError, ValueError, http.client.HTTPException):
                        continue
                    occupied = path + suffix
                    break
            if occupied:
                if value == "r":
                    continue
                print(f"已有 WebSocket 端点 {occupied}，请改选路径。")
                break
            uncertain = site_probe(domain, path) if existing else None
            if existing and not uncertain:
                matchers = {key for site in host_routes(config, domain) for obj in objects(site)
                            for key in obj if key in ("expression", "path_regexp")}
                if matchers:
                    uncertain = "包含动态匹配规则 " + ", ".join(sorted(matchers))
            if uncertain and not yes(f"现有站点响应：{uncertain}。确认将这四个路径的 WebSocket 请求交给 rVPN？", False):
                break
            return path
        else:
            raise ValueError("找不到空闲随机路径，请检查站点的路径匹配规则")


def snippet(state):
    paths = " ".join(state["path"] + suffix for suffix in SUFFIXES)
    return (f"@rvpn_ws {{\n path {paths}\n header Upgrade websocket\n header_regexp Connection (?i)\\bupgrade\\b\n}}\n"
            f"handle @rvpn_ws {{\n reverse_proxy 127.0.0.1:{state['port']}\n}}\n")


def install_route(state, location):
    target, index = location or (CADDY.resolve(), None)
    original = target.read_text() if target.exists() else ""
    route = ETC / "caddy-routes"
    include = f"import {route}"
    content = snippet(state)
    if route.exists() and route.read_text() != content:
        raise ValueError(f"配置片段已存在且内容不同：{route}")
    if any(line.strip() == include for line in original.splitlines()):
        if not location:
            raise ValueError(f"{include} 已在其他站点使用，请检查 Caddy 配置")
        caddy_command("validate", "--adapter", "caddyfile", "--config", str(CADDY))
        run("systemctl", "enable", "--now", "caddy")
        run("systemctl", "reload", "caddy")
        return
    if index is None:
        fallback = (f"reverse_proxy 127.0.0.1:{state['mirror_port']}" if state["mirror"] else
                    'respond "Site is online." 200')
        updated = original + f"\n{state['domain']} {{\n    {include}\n    handle {{\n        {fallback}\n    }}\n}}\n"
    else:
        lines = original.splitlines(True)
        # Promote an explicitly HTTP-only site to Caddy automatic HTTPS.
        header = lines[index - 1]
        lines[index - 1] = re.sub(r"^(\s*)(?:http://)?(" + re.escape(state["domain"]) +
                                  r")(?::80)?(?=\s*\{)", r"\1\2", header, flags=re.I)
        lines.insert(index, f"    {include}\n")
        updated = "".join(lines)
    backup = ETC / "backups" / (target.name + "-" + secrets.token_hex(6))
    write(backup, original, 0o600)
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o644
    previous_route = route.exists()
    write(route, content)
    try:
        write(target, updated, mode)
        caddy_command("validate", "--adapter", "caddyfile", "--config", str(CADDY))
        run("systemctl", "enable", "--now", "caddy")
        run("systemctl", "reload", "caddy")
        for suffix in SUFFIXES:
            retry(lambda: upgrade(state["domain"], 443, state["path"] + suffix, local_tls=True), 100)
    except Exception:
        write(target, original, mode)
        if not previous_route:
            route.unlink()
        subprocess.run(["systemctl", "reload", "caddy"], check=False)
        raise


def download(url, path):
    run("curl", "--fail", "--silent", "--show-error", "--location", "--retry", "3",
        "--proto", "=https", "--proto-redir", "=https", "-o", str(path), url)


def install_dependencies(has_caddy):
    run("apt-get", "update")
    run("apt-get", "install", "-y", "ca-certificates", "curl")
    if has_caddy:
        return
    policy = subprocess.check_output(["apt-cache", "policy", "caddy"], text=True,
                                     env={**os.environ, "LC_ALL": "C"})
    if not re.search(r"Candidate:\s+\d", policy):
        if not yes("发行版软件源没有 Caddy，添加 Caddy 官方 stable 签名软件源？"):
            raise ValueError("缺少可安装的 Caddy 软件包")
        run("apt-get", "install", "-y", "gnupg")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            source = "https://dl.cloudsmith.io/public/caddy/stable"
            download(source + "/gpg.key", work / "key.asc")
            download(source + "/debian.deb.txt", work / "caddy.list")
            run("gpg", "--batch", "--dearmor", "--output", str(work / "key.gpg"), str(work / "key.asc"))
            run("install", "-m", "0644", str(work / "key.gpg"), "/usr/share/keyrings/caddy-stable-archive-keyring.gpg")
            write(Path("/etc/apt/sources.list.d/caddy-stable.list"), (work / "caddy.list").read_text())
        run("apt-get", "update")
    run("apt-get", "install", "-y", "caddy")


def release(repo, tag, archive, sums, work, binary):
    prefix = f"https://github.com/{repo}/releases/" + ("latest/download" if tag == "latest" else f"download/{tag}")
    download(f"{prefix}/{sums}", work / sums)
    download(f"{prefix}/{archive}", work / archive)
    checksum = [s.split()[0] for s in (work / sums).read_text().splitlines()
                if len(s.split()) == 2 and s.split()[1].lstrip("*") == archive]
    digest = hashlib.sha256()
    with (work / archive).open("rb") as src:
        for block in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(block)
    if checksum != [digest.hexdigest()]:
        raise ValueError(f"{archive} SHA-256 校验失败")
    with tarfile.open(work / archive) as tar:
        for name in [binary] + (["config.example.toml"] if binary == "mirrorproxy-server" else []):
            member = tar.getmember(name)
            if not member.isfile():
                raise ValueError(f"无效的归档成员 {name}")
            with (work / name).open("wb") as out:
                shutil.copyfileobj(tar.extractfile(member), out)
        if binary == "mirrorproxy-server":
            for member in tar:
                parts = Path(member.name).parts
                if member.isfile() and parts[:1] == ("geoip",) and ".." not in parts:
                    dest = Path("/usr/local/share/rvpn-mirrorproxy").joinpath(*parts)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with dest.open("wb") as out:
                        shutil.copyfileobj(tar.extractfile(member), out)
    install_binary(work / binary, binary)


def install_binary(source, binary):
    # Atomic executable replacement even if the previous inode is running.
    with tempfile.NamedTemporaryFile(dir=BIN, delete=False) as out, source.open("rb") as src:
        shutil.copyfileobj(src, out)
        os.fchmod(out.fileno(), 0o755)
    os.replace(out.name, BIN / binary)


def service(name, directory, command, env="", tun=False):
    # TUN setup runs ip/iptables and checks host routes and Docker IPAM.
    identity = ("ProtectSystem=full\nProtectHome=yes\nPrivateTmp=yes\n"
                "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n" if tun
                else "DynamicUser=yes\n")
    unit = (f"[Unit]\nDescription={name}\nAfter=network.target\n\n[Service]\n"
            f"{identity}StateDirectory={directory.name}\nWorkingDirectory={directory}\n{env}"
            f"ExecStart={command}\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\n"
            "[Install]\nWantedBy=multi-user.target\n")
    write(UNITS / (name + ".service"), unit)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", name)
    run("systemctl", "restart", name)


def upgrade(host, port, path, local_tls=False, public_tls=False):
    key = base64.b64encode(os.urandom(16)).decode()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    if local_tls or public_tls:
        ctx = ssl._create_unverified_context() if local_tls else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=4, context=ctx)
        if local_tls:
            conn._create_connection = lambda _, timeout, *args: socket.create_connection(("127.0.0.1", port), timeout)
    try:
        conn.request("GET", path, headers={"Host":host, "Connection":"Upgrade", "Upgrade":"websocket",
                     "Sec-WebSocket-Version":"13", "Sec-WebSocket-Key":key})
        response = conn.getresponse()
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if response.status != 101 or response.getheader("Sec-WebSocket-Accept") != accept:
            raise ValueError(f"{host}{path} WebSocket Upgrade 返回 {response.status}")
    finally:
        conn.close()


def retry(check, seconds):
    end = time.monotonic() + seconds
    while True:
        try:
            return check()
        except (OSError, ValueError, http.client.HTTPException) as error:
            if time.monotonic() >= end:
                raise RuntimeError(f"验证失败：{error}") from error
            time.sleep(2)


def listeners():
    return run("ss", "-H", "-ltnp", capture=True).splitlines()


def port_choice(prompt, default, reserved):
    while True:
        value = input(f"{prompt} [{default}]：").strip() or str(default)
        if value.isdigit() and 1024 <= int(value) <= 65535 and int(value) not in reserved:
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1", int(value)))
                    return int(value)
                except OSError:
                    pass
        print("端口被占用或不在 1024–65535 范围内")


def deploy(args):
    global CADDY
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise ValueError("请在 Debian / Ubuntu 上使用 sudo 运行")
    state = json.loads(STATE.read_text()) if STATE.exists() else None
    if args.show_link:
        if not state:
            raise ValueError("找不到此安装器创建的部署")
        show_link(state)
        return
    if args.setup_ech:
        if not state or not state.get("installed_caddy"):
            raise ValueError("ECH 向导适用于本安装器全新安装的 Caddy")
        setup_ech(state, caddy_service_config())
        return
    if not re.search(r'^ID="?(debian|ubuntu)"?$', Path("/etc/os-release").read_text(), re.M):
        raise ValueError("支持 Debian / Ubuntu")
    if not Path("/run/systemd/system").exists():
        raise ValueError("需要运行中的 systemd")
    arch = {"x86_64":"x86_64", "aarch64":"aarch64"}.get(os.uname().machine)
    if not arch:
        raise ValueError("仅支持 x86_64 / ARM64")
    if not shutil.which("ss"):
        if not yes("安装 iproute2 以检查监听端口？"):
            return
        run("apt-get", "update")
        run("apt-get", "install", "-y", "iproute2")
    for line in listeners():
        if line.split()[3].rsplit(":", 1)[-1] in ("80", "443") and '"caddy"' not in line:
            raise ValueError(f"Web 端口已由其他进程占用：{line}")
    has_caddy = bool(shutil.which("caddy"))
    installed = [name for name in ("caddy", "nginx", "apache2") if shutil.which(name)]
    print("Web 服务检测：" + ("、".join(installed) or "未发现"))
    if has_caddy:
        CADDY = caddy_service_config()
    config = adapted() if has_caddy else {}
    if state:
        domain = state["domain"]
    else:
        for target in (ETC / "server.toml", DATA, BIN / "rvpn-server", UNITS / "rvpn-server.service"):
            if target.exists():
                raise ValueError(f"检测到非本脚本管理的 rVPN：{target}")
        if has_unit("rvpn-server"):
            raise ValueError("检测到已有 rvpn-server 服务")
        domain = input("公网域名（A/AAAA 记录应指向本机）：").strip().lower()
        if not DOMAIN.fullmatch(domain):
            raise ValueError("请输入有效的完整域名")
    location = site_location(config, domain)
    if not state:
        mirror_present = any(p.exists() for p in (BIN / "mirrorproxy-server", MIRROR, Path("/etc/mirrorproxy"),
                                                   Path("/opt/mirrorproxy"))) or bool(shutil.which("mirrorproxy-server"))
        mirror_present |= any(has_unit(name) for name in ("mirrorproxy", "mirrorproxy-server", "rvpn-mirrorproxy"))
        existing_sites = bool(config.get("apps", {}).get("http", {}).get("servers"))
        clean = not location and not existing_sites and not mirror_present and not {"nginx", "apache2"}.intersection(installed)
        mirror = clean and yes("同时部署 MirrorProxy 作为此域名的公开镜像站？（推荐）")
        tun = yes("启用服务端 TUN 和内核 IPv4 转发？")
        path = choose_path(config, domain, location)
        port = port_choice("rVPN 本机端口", 8091, set())
        state = dict(domain=domain, tun=tun, path=path, port=port, mirror=mirror, installed_caddy=not has_caddy,
                     mirror_port=port_choice("MirrorProxy 本机端口", 3000, {port}) if mirror else None)
    print(f"{domain}，Caddy HTTPS → {state['path']} → 127.0.0.1:{state['port']}\n"
          f"站点配置：{location[0] if location else CADDY}；rVPN 配置：{ETC}/server.toml\n"
          f"systemd：caddy、rvpn-server" + (f"、rvpn-mirrorproxy（127.0.0.1:{state['mirror_port']}）" if state['mirror'] else ""))
    print("复用已安装的 Caddy。" if has_caddy else "将通过 apt 安装 Caddy，并启用 HTTPS。")
    if state.get("tun"):
        print("TUN 将使用 10.200.0.0/24，并启用 IPv4 转发和 iptables。")
    if location:
        print("现有站点将保留原有处理规则；仅 HTTP 的域名站点将启用 Caddy 自动 HTTPS。")
    if not yes("确认安装依赖、配置并启动以上服务？", False):
        return
    if state.get("tun"):
        if not Path("/dev/net/tun").exists():
            raise ValueError("服务端 TUN 需要 /dev/net/tun；请启用设备或选择关闭 TUN")
        run("apt-get", "update")
        run("apt-get", "install", "-y", "iproute2", "iptables")
        forwarding = Path("/etc/sysctl.d/90-rvpn-forwarding.conf")
        write(forwarding, "net.ipv4.ip_forward = 1\n")
        run("sysctl", "-p", str(forwarding))
    install_dependencies(has_caddy)
    if not STATE.exists():
        write(STATE, json.dumps(state, indent=2), 0o600)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        packaged = Path(__file__).resolve().with_name("rvpn-server")
        if args.release is None and packaged.is_file():
            run("sha256sum", "--check", "--status", "rvpn-server.sha256", cwd=packaged.parent)
            install_binary(packaged, "rvpn-server")
        else:
            release("SparkHell/rVPN", args.release or "nightly", f"rvpn-server-linux-{arch}.tar.gz",
                    "SHA256SUMS.txt", work, "rvpn-server")
        if state["mirror"]:
            target = "x86_64-unknown-linux-musl" if arch == "x86_64" else "aarch64-unknown-linux-gnu"
            archive = f"mirrorproxy-server-{target}.tar.gz"
            release("inbjo/MirrorProxy", args.mirror_release, archive, archive + ".sha256", work, "mirrorproxy-server")
            mirror_config = ETC / "mirrorproxy.toml"
            if not mirror_config.exists():
                template = (work / "config.example.toml").read_text()
                for field, val in (("listen_addr", f"127.0.0.1:{state['mirror_port']}"), ("public_base_url", f"https://{domain}")):
                    template, count = re.subn(rf"^{field} = .*", f'{field} = "{val}"', template, count=1, flags=re.M)
                    if count != 1:
                        raise ValueError(f"MirrorProxy 示例配置缺少 {field}")
                write(mirror_config, template)
            credentials = ETC / "mirrorproxy.env"
            if not credentials.exists():
                write(credentials, f"MIRRORPROXY_ADMIN_PASSWORD={secrets.token_urlsafe(30)}\nMIRRORPROXY_MASTER_KEY={secrets.token_hex(32)}\n", 0o600)
            service("rvpn-mirrorproxy", MIRROR, f"{BIN}/mirrorproxy-server --config {mirror_config} serve",
                    f"EnvironmentFile={credentials}\nExecStartPre=/bin/cp -rn /usr/local/share/rvpn-mirrorproxy/geoip {MIRROR}/\n")
            print(f"MirrorProxy 管理员初始凭据保存在 {credentials}（仅 root 可读）")
    server_config = ETC / "server.toml"
    if not server_config.exists():
        write(server_config, f"""[server]
bind_address = "127.0.0.1:{state['port']}"
websocket_path = "{state['path']}"
identity_key_file = "{DATA}/identity.key"
prekey_bundle_file = "{DATA}/prekey-bundle.json"
[server.logging]
file_enabled = false
[server.tun]
enabled = {str(state.get("tun", False)).lower()}
""")
    service("rvpn-server", DATA, f"{BIN}/rvpn-server --config {server_config}", tun=state.get("tun", False))
    print("正在验证本机 rVPN WebSocket 服务…", flush=True)
    retry(lambda: upgrade(domain, state["port"], state["path"]), 20)
    # Apt may create a stock Caddyfile. Re-read imports before touching the site.
    current = adapted()
    current_location = site_location(current, domain)
    if location != current_location:
        raise ValueError("安装期间站点位置发生变化，请重跑并确认目标")
    install_route(state, current_location)
    print("正在验证公网 DNS、HTTPS 证书和四条 WebSocket 路由…", flush=True)
    for suffix in SUFFIXES:
        retry(lambda: upgrade(domain, 443, state["path"] + suffix, public_tls=True), 90)
    if state["mirror"]:
        def mirror_ready():
            for path in ("/", "/api/public-config"):
                with urllib.request.urlopen(f"https://{domain}{path}", timeout=5) as response:
                    if path == "/":
                        if "mirrorproxy" not in response.read(1024*1024).decode().lower():
                            raise ValueError("首页未返回 MirrorProxy")
                    else:
                        if not isinstance(json.load(response), dict):
                            raise ValueError("MirrorProxy API 响应无效")
        retry(mirror_ready, 30)
    if state.get("installed_caddy") and not caddy_ech.DROPIN.exists() and yes("是否运行 ECH 配置向导？", False):
        try:
            setup_ech(state, CADDY)
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
            print(f"ECH 步骤未完成：{error}。可使用 --setup-ech 重试。", file=sys.stderr)
            retry(lambda: upgrade(domain, 443, state["path"], public_tls=True), 20)
    show_link(state)


def setup_ech(state, config):
    def check_site():
        retry(lambda: upgrade(state["domain"], 443, state["path"], local_tls=True), 30)
    caddy_ech.configure(state, config, DOMAIN, run, write, download, yes, check_site)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--show-link", action="store_true")
    mode.add_argument("--setup-ech", action="store_true", help="configure ECH or check DNS publication")
    parser.add_argument("--release", help="override bundled server; source checkouts default to nightly")
    parser.add_argument("--mirror-release", default="latest", help="MirrorProxy release tag")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "请使用 sudo 运行安装脚本\n")
    try:
        with open("/run/rvpn-install.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            deploy(args)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, EOFError, KeyError) as error:
        parser.exit(1, f"安装未完成：{error}\n")


if __name__ == "__main__":
    main()
