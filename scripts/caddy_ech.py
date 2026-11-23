"""Optional ECH setup for a Caddy installation created by the rVPN installer."""
import getpass
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import warnings
from urllib.parse import urlencode

BINARY = Path("/usr/local/lib/rvpn/caddy")
DROPIN = Path("/etc/systemd/system/caddy.service.d/rvpn-ech.conf")
ENV = Path("/etc/rvpn/caddy-dns.env")

# All module paths are selected locally. NS answers are only provider hints.
PROVIDERS = {
    "cloudflare": (("ns.cloudflare.com",), ("CF_API_TOKEN",)),
    "alidns": (("hichina.com", "alidns.com", "alidns.net"), ("ALIYUN_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_SECRET")),
    "tencentcloud": (("dnspod.net", "dnspod.cn", "dnspod.com"), ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY")),
    "route53": ((), ("AWS_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")),
}


def dns_records(host, rrtype):
    output = subprocess.check_output(["dig", "+time=3", "+tries=1", "+noall", "+comments", "+answer",
                                      host + ".", rrtype], text=True)
    if not re.search(r"status: (NOERROR|NXDOMAIN),", output):
        raise ValueError(f"DNS 查询失败：{host} {rrtype}")
    records = []
    for line in output.splitlines():
        fields = line.split(maxsplit=4)
        if len(fields) == 5 and fields[0].lower() == host + "." and fields[3] == rrtype:
            records.append(fields[4])
    return records


def authority(domain):
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        zone = ".".join(labels[i:])
        ns = [value.lower().rstrip(".") for value in dns_records(zone, "NS")]
        if ns:
            return zone, ns
    return None, []


def identify(nameservers):
    def match(ns):
        if re.fullmatch(r"ns\d+\.aliyun\.com", ns):
            return "alidns"
        if re.fullmatch(r"ns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)", ns):
            return "route53"
        for provider, (suffixes, _) in PROVIDERS.items():
            if any(ns.endswith("." + suffix) for suffix in suffixes):
                return provider
    matches = {match(ns) for ns in nameservers}
    return matches.pop() if len(matches) == 1 else None


def global_config(original, public, provider):
    if provider == "cloudflare":
        directive = "dns cloudflare {env.CF_API_TOKEN}"
    elif provider == "route53":
        directive = "dns route53"
    else:
        fields = ("access_key_id", "access_key_secret") if provider == "alidns" else ("secret_id", "secret_key")
        body = "\n".join(f"            {key} {{env.{env}}}" for key, env in zip(fields, PROVIDERS[provider][1]))
        directive = f"dns {provider} {{\n{body}\n        }}"
    block = f"    ech {public} {{\n        {directive}\n    }}\n"
    # A clean install starts from the package Caddyfile. Keep any existing
    # global options and all site blocks byte-for-byte outside the insertion.
    first = re.search(r"(?m)^[ \t]*(?!#)(\S[^\n]*)", original)
    if first and first[1].split("#")[0].strip() == "{":
        end = original.find("\n", first.end())
        if end < 0:
            raise ValueError("Caddy 全局配置块不完整")
        return original[:end + 1] + block + original[end + 1:]
    return "{\n" + block + "}\n" + original


def dns_status(domain):
    records = dns_records(domain, "HTTPS")
    if any(re.search(r'(?:^|\s)ech="?[^"\s]+', record) for record in records):
        print(f"{domain} 的 DNS HTTPS 记录已包含 ech 参数。请用客户端使用部署域名、DoH 和 [network].ech_mode = 'required' 连接验证握手。")
    else:
        print(f"尚未查询到 {domain} 的 ech 参数。请检查 journalctl -u caddy 和 dig HTTPS {domain}；"
              "DNS 生效前客户端可使用 prefer 模式。")


def validate(binary, config, credentials):
    # Some third-party modules include their input in provisioning errors.
    result = subprocess.run([binary, "validate", "--config", config, "--adapter", "caddyfile"],
                            env={**os.environ, **credentials}, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    if result.returncode:
        raise ValueError("Caddy ECH 配置校验失败，请检查域名、DNS 模块及凭据格式")


def read_credentials(provider):
    if provider == "cloudflare":
        print("Cloudflare API Token 需要目标区域的 Zone:Read 和 DNS:Edit 权限。")
    credentials = {}
    for field in PROVIDERS[provider][1]:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass(field + "：")
        except getpass.GetPassWarning as error:
            raise ValueError("请在支持隐藏输入的终端中运行 ECH 向导") from error
        if not re.fullmatch(r"[A-Za-z0-9_./+=:@-]+", value):
            raise ValueError(f"{field} 为空或格式无效")
        credentials[field] = value
    return credentials


def env_text(credentials):
    return "".join(f"{key}={value}\n" for key, value in credentials.items())


def update_credentials(config, run, write, check_site):
    previous = ENV.read_text()
    keys = {line.partition("=")[0] for line in previous.splitlines()}
    provider = next((name for name, (_, fields) in PROVIDERS.items() if set(fields) == keys), None)
    if not provider:
        raise ValueError("无法识别已有凭据文件中的厂商")
    credentials = read_credentials(provider)
    validate(BINARY, config, credentials)
    try:
        write(ENV, env_text(credentials), 0o600)
        run("systemctl", "restart", "caddy")
        check_site()
    except BaseException:
        write(ENV, previous, 0o600)
        run("systemctl", "restart", "caddy")
        raise


def configure(state, config, domain_pattern, run, write, download, yes, check_site):
    domain = state["domain"]
    if not shutil.which("dig"):
        run("apt-get", "install", "-y", "dnsutils")
    if DROPIN.exists():
        if yes("是否重新输入 DNS 凭据并重启 Caddy？回车仅检查 DNS 发布状态。", False):
            update_credentials(config, run, write, check_site)
        dns_status(domain)
        return
    zone, names = authority(domain)
    detected = identify(names)
    print(f"权威 DNS 区域：{zone or '未知'}；NS：{', '.join(names) or '未知'}")
    if dns_records(domain, "CNAME"):
        raise ValueError("部署域名存在 CNAME。Caddy 自动发布 HTTPS 记录需要直接解析到源站的 A/AAAA 记录。")
    print("若 TLS 由 CDN 终止，请在 CDN 开启 ECH。源站 Caddy 发布 ECH 需要域名直连本机。")
    choices = ", ".join(PROVIDERS)
    provider = input(f"确认 DNS 厂商（{choices}，回车选 {detected or '跳过'}）：").strip().lower() or detected
    if not provider:
        return
    if provider not in PROVIDERS:
        raise ValueError("该 DNS 厂商暂未适配")
    public = input("ECH 外层公开域名（A/AAAA 指向本机，建议与部署域名不同）：").strip().lower()
    if not domain_pattern.fullmatch(public):
        raise ValueError("ECH 外层名称须为有效域名")
    if not (dns_records(public, "A") or dns_records(public, "AAAA")):
        raise ValueError("ECH 外层域名还没有 A/AAAA 地址")
    if public == domain:
        print("外层公开域名与部署域名相同，握手仍会公开这个名称。")
    print("ECH 是该 Caddy 实例的全局设置，可以为它管理的站点发布 HTTPS 记录。")
    if not yes(f"通过 Caddy 官方构建服务编译 dns.providers.{provider}，配置并重启 Caddy，允许其发布 HTTPS 记录？", False):
        return
    original = config.read_text()
    if re.search(r"(?m)^\s*ech\s", original) or ENV.exists() or BINARY.exists():
        raise ValueError("检测到已有 ECH 配置或自定义二进制，请检查后重试")
    arch = {"x86_64":"amd64", "aarch64":"arm64"}[platform.machine()]
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=BINARY.parent) as tmp:
        candidate = Path(tmp) / "caddy"
        query = urlencode({"os":"linux", "arch":arch, "p":"github.com/caddy-dns/" + provider})
        download("https://caddyserver.com/api/download?" + query, candidate)
        candidate.chmod(0o755)
        version = run(str(candidate), "version", capture=True).strip()
        match = re.match(r"v(\d+)\.(\d+)", version)
        if not match or tuple(map(int, match.groups())) < (2, 10):
            raise ValueError(f"Caddy 版本不支持 ECH：{version}")
        if "dns.providers." + provider not in run(str(candidate), "list-modules", capture=True).splitlines():
            raise ValueError("构建产物缺少所选 DNS 模块")
        print(f"已验证 {version.split()[0]} 和 dns.providers.{provider}。"
              "请使用仅限目标 DNS 区域的凭据，需要读取区域、读取及修改 HTTPS 记录的权限。")
        credentials = read_credentials(provider)
        updated = global_config(original, public, provider)
        with tempfile.NamedTemporaryFile(mode="w", dir=config.parent) as staged:
            staged.write(updated)
            staged.flush()
            validate(candidate, staged.name, credentials)
        if config.read_text() != original:
            raise ValueError("Caddyfile 已被修改，请重试")
        backup = ENV.parent / "backups" / "Caddyfile.before-ech"
        write(backup, original, 0o600)
        mode = config.stat().st_mode & 0o777
        try:
            candidate.replace(BINARY)
            write(ENV, env_text(credentials), 0o600)
            # The distribution unit often uses --environ, which logs every
            # environment variable. Both commands must use the custom build.
            write(DROPIN, f"[Service]\nEnvironmentFile={ENV}\nExecStart=\n"
                  f"ExecStart={BINARY} run --adapter caddyfile --config {config}\nExecReload=\n"
                  f"ExecReload={BINARY} reload --adapter caddyfile --config {config} --force\n")
            write(config, updated, mode)
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", "caddy")
            check_site()
        except BaseException:
            write(config, original, mode)
            for path in (DROPIN, ENV, BINARY):
                path.unlink(missing_ok=True)
            run("systemctl", "daemon-reload")
            run("systemctl", "restart", "caddy")
            raise
    print("Caddy 已加载 ECH 配置。")
    dns_status(domain)
