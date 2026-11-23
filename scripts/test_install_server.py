import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import install_server as installer


class CaddyDeploymentTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.caddy = root / "Caddyfile"
        self.site = root / "sites" / "app"
        self.site.parent.mkdir()
        self.site.write_text("app.example.com {\n reverse_proxy localhost:3000\n}\n")
        self.caddy.write_text("import sites/*\n")
        self.state = dict(domain="app.example.com", path="/cw/ws", port=8091, mirror=False)
        self.config = {"routes": [{"match": [{"host": ["app.example.com"]}],
                                  "handle": [{"routes": [{"match": [{"path": ["/cw/ws/tun"]}]}]}]}]}
        for key, value in (("CADDY", self.caddy), ("ETC", root / "rvpn")):
            mock = patch.object(installer, key, value)
            mock.start()
            self.addCleanup(mock.stop)

    def test_child_path_conflict_and_random_alternative(self):
        with patch("builtins.input", side_effect=["", "r"]), patch.object(installer, "site_probe", return_value=None), \
                patch.object(installer, "upgrade", side_effect=ValueError("404")):
            path = installer.choose_path(self.config, "app.example.com", True)
        self.assertRegex(path, r"^/cw/[a-f0-9]{16}/ws$")
        self.assertIsNone(installer.conflict(self.config, "elsewhere.example.com", "/cw/ws"))

    def test_import_preserves_site_and_is_idempotent(self):
        location = installer.site_location(self.config, "app.example.com")
        self.assertEqual(location, (self.site, 1))
        with patch.object(installer, "run"), patch.object(installer, "upgrade"):
            installer.install_route(self.state, location)
            first = self.site.read_bytes()
            installer.install_route(self.state, location)
            self.assertEqual(self.site.read_bytes(), first)
        self.assertEqual(self.caddy.read_text(), "import sites/*\n")
        self.assertIn("reverse_proxy localhost:3000", self.site.read_text())
        self.assertEqual(self.site.read_text().count("import "), 1)

    def test_caddy_reload_failure_rolls_back_only_modified_files(self):
        before = self.site.read_bytes()
        def run(*args, **kwargs):
            if args[:2] == ("systemctl", "reload"):
                raise subprocess.CalledProcessError(1, args)
        with patch.object(installer, "run", side_effect=run), patch.object(subprocess, "run"):
            with self.assertRaises(subprocess.CalledProcessError):
                installer.install_route(self.state, (self.site, 1))
        self.assertEqual(self.site.read_bytes(), before)
        self.assertFalse((installer.ETC / "caddy-routes").exists())

    def test_new_site_uses_selected_fallback(self):
        for use_mirror in [True, False]:
            self.caddy.write_text("")
            state = dict(self.state, mirror=use_mirror, mirror_port=3000)
            with patch.object(installer, "run"), patch.object(installer, "upgrade"):
                installer.install_route(state, None)
            self.assertEqual("reverse_proxy 127.0.0.1:3000" in self.caddy.read_text(), use_mirror)

    def test_link_only_exports_public_material(self):
        import base64
        bundle = {key: "public" for key in installer.PUBLIC_KEYS[:4]}
        bundle["signed_prekey_private"] = "private"
        uri = installer.link("wss://app.example.com/cw/ws", bundle)
        encoded = uri.removeprefix("rVPN://")
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(payload["address"], "wss://app.example.com/cw/ws")
        self.assertNotIn("signed_prekey_private", payload["bundle"])


class EchDeploymentTest(unittest.TestCase):
    def test_delegation_and_mixed_or_unrecognized_providers(self):
        from caddy_ech import authority, identify
        with patch("caddy_ech.dns_records", side_effect=[[], ["vip1.alidns.com."]]) as lookup:
            zone, names = authority("vpn.team.example.com")
        self.assertEqual(zone, "team.example.com")
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(identify(names), "alidns")
        for ns, provider in [("a.ns.cloudflare.com", "cloudflare"), ("ns-42.awsdns-01.co.uk", "route53"),
                             ("v4.dnspod.cn", "tencentcloud"), ("ns3.aliyun.com", "alidns"), ("ns.cloudflare.com.unknown.test", None)]:
            self.assertEqual(identify([ns]), provider)
        self.assertIsNone(identify(["a.ns.cloudflare.com", "unknown.test"]))

    def test_preserves_global_options_and_site_config(self):
        from caddy_ech import global_config
        for original in ("# one\n{ # global\n  debug\n}\nexample.com {\n}\n", "# stock\n:80 {\n}\n"):
            output = global_config(original, "edge.example.com", "cloudflare")
            self.assertEqual(output.count("ech edge.example.com"), 1)
            self.assertIn("dns cloudflare {env.CF_API_TOKEN}", output)
            self.assertTrue(output.endswith(original[original.index("debug"):] if "debug" in original else original))

    def test_rolls_back_on_restart_failure(self):
        import caddy_ech as ech
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "Caddyfile"
            config.write_text("app.example.com {\n}\n")
            def run(*args, **kwargs):
                if args[1] == "version":
                    return "v2.11.9"
                if args[1] == "list-modules":
                    return "dns.providers.cloudflare"
                if args[1] == "restart" and ech.DROPIN.exists():
                    raise RuntimeError("failed to start")
            with patch.multiple(ech, BINARY=root/"lib"/"caddy", ENV=root/"creds", DROPIN=root/"unit"), \
                 patch.object(ech, "authority", return_value=("example.com", ["a.ns.cloudflare.com"])), \
                 patch.object(ech, "dns_records", side_effect=[[], ["192.0.2.1"]]), \
                 patch.object(ech, "validate"), patch.object(ech, "read_credentials", return_value={"CF_API_TOKEN":"dummy"}), \
                 patch("builtins.input", side_effect=["", "outer.example.com"]):
                with self.assertRaisesRegex(RuntimeError, "failed to start"):
                    ech.configure({"domain":"app.example.com"}, config, installer.DOMAIN, run, installer.write,
                                  lambda _, path: path.write_bytes(b"fixture"), lambda *_: True, lambda: None)
                self.assertFalse(any(p.exists() for p in (ech.BINARY, ech.ENV, ech.DROPIN)))
                self.assertEqual(config.read_text(), "app.example.com {\n}\n")


if __name__ == "__main__":
    unittest.main()
