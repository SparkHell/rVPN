//! Scope Windows DNS changes to a running proxy generation.
use std::{collections::BTreeMap, io, ptr};

use anyhow::{Context, Result};
use windows_sys::{
    core::{w, GUID},
    Win32::{
        NetworkManagement::IpHelper::{
            ConvertInterfaceLuidToGuid, FreeMibTable, GetIpForwardTable2, DNS_INTERFACE_SETTINGS,
            DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
            MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        },
        Networking::WinSock::AF_UNSPEC,
        System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
    },
};
use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

type SetDns = unsafe extern "system" fn(GUID, *const DNS_INTERFACE_SETTINGS) -> u32;

#[derive(Clone)]
struct Adapter {
    index: u32,
    guid: GUID,
    registry_id: String,
}

struct Settings {
    adapter: Adapter,
    ipv6: bool,
    original: String,
}

pub(crate) struct SystemDns {
    set_dns: SetDns,
    read_static: fn(&str, bool) -> Result<String>,
    changed: Vec<Settings>,
}

impl SystemDns {
    pub(crate) fn take_over() -> Result<Self> {
        // Resolve dynamically so older Windows can still run ordinary proxy mode.
        let module = unsafe { GetModuleHandleW(w!("iphlpapi.dll")) };
        let symbol = unsafe { GetProcAddress(module, c"SetInterfaceDnsSettings".as_ptr().cast()) }
            .context("接管系统 DNS 需要 Windows 10 版本 2004 或更新版本")?;
        let set_dns: SetDns = unsafe { std::mem::transmute(symbol) };
        let guard = Self {
            set_dns,
            read_static: static_dns,
            changed: Vec::new(),
        };
        guard.apply(default_route_adapters()?)
    }

    fn apply(mut self, adapters: Vec<Adapter>) -> Result<Self> {
        for adapter in adapters {
            for ipv6 in [false, true] {
                let settings = Settings {
                    original: (self.read_static)(&adapter.registry_id, ipv6)?,
                    adapter: adapter.clone(),
                    ipv6,
                };
                if settings.original != settings.loopback() {
                    self.set(&settings, settings.loopback())?;
                    self.changed.push(settings);
                }
            }
        }
        tracing::info!("Windows system DNS directed to the rVPN IPv4 and IPv6 listeners");
        Ok(self)
    }

    fn set(&self, settings: &Settings, servers: &str) -> Result<()> {
        let mut servers: Vec<u16> = servers.encode_utf16().chain([0]).collect();
        let options = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: (DNS_SETTING_NAMESERVER | if settings.ipv6 { DNS_SETTING_IPV6 } else { 0 })
                as u64,
            NameServer: servers.as_mut_ptr(),
            ..Default::default()
        };
        status(unsafe { (self.set_dns)(settings.adapter.guid, &options) }).with_context(|| {
            format!(
                "无法设置网卡 {} 的 IPv{} DNS，请以管理员权限运行 rVPN",
                settings.adapter.index,
                if settings.ipv6 { 6 } else { 4 }
            )
        })
    }
}

impl Settings {
    fn loopback(&self) -> &'static str {
        if self.ipv6 {
            "::1"
        } else {
            "127.0.0.1"
        }
    }
}

impl Drop for SystemDns {
    fn drop(&mut self) {
        while let Some(settings) = self.changed.pop() {
            // Preserve changes explicitly made by the user while rVPN was running.
            match (self.read_static)(&settings.adapter.registry_id, settings.ipv6) {
                Ok(current) if current == settings.loopback() => {
                    if let Err(error) = self.set(&settings, &settings.original) {
                        tracing::error!("Failed to restore Windows DNS: {error:#}");
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!("Failed to check Windows DNS before restoring: {error:#}")
                }
            }
        }
    }
}

fn static_dns(registry_id: &str, ipv6: bool) -> Result<String> {
    let service = if ipv6 { "Tcpip6" } else { "Tcpip" };
    let path =
        format!(r"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces\{registry_id}");
    let result = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(&path)
        .and_then(|key| key.get_value("NameServer"));
    match result {
        // An absent or empty static list uses the automatic DNS configuration.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        other => other
            .with_context(|| format!("Could not read DNS settings for {registry_id} ({service})")),
    }
}

fn default_route_adapters() -> Result<Vec<Adapter>> {
    struct RouteTable(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for RouteTable {
        fn drop(&mut self) {
            unsafe { FreeMibTable(self.0.cast()) }
        }
    }

    let mut table = ptr::null_mut();
    status(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })
        .context("无法读取 Windows 默认路由")?;
    let table = RouteTable(table);
    let mut adapters = BTreeMap::new();
    // IP Helper allocates a variable-length table, released by FreeMibTable.
    let routes: &[MIB_IPFORWARD_ROW2] = unsafe {
        std::slice::from_raw_parts(
            ptr::addr_of!((*table.0).Table).cast(),
            (*table.0).NumEntries as usize,
        )
    };
    for route in routes
        .iter()
        .filter(|route| route.DestinationPrefix.PrefixLength == 0 && !route.Loopback)
    {
        if let std::collections::btree_map::Entry::Vacant(entry) =
            adapters.entry(route.InterfaceIndex)
        {
            let mut guid = GUID::default();
            status(unsafe { ConvertInterfaceLuidToGuid(&route.InterfaceLuid, &mut guid) })?;
            let id = uuid::Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4);
            let registry_id = format!("{{{id}}}");
            entry.insert(Adapter {
                index: route.InterfaceIndex,
                guid,
                registry_id,
            });
        }
    }
    anyhow::ensure!(!adapters.is_empty(), "没有带默认路由的 Windows 网卡");
    Ok(adapters.into_values().collect())
}

fn status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static SERVERS: RefCell<[String; 2]> = RefCell::default();
        static FAIL_V6: Cell<bool> = const { Cell::new(false) };
    }

    fn read(_: &str, ipv6: bool) -> Result<String> {
        Ok(SERVERS.with_borrow(|values| values[ipv6 as usize].clone()))
    }

    unsafe extern "system" fn write(_: GUID, options: *const DNS_INTERFACE_SETTINGS) -> u32 {
        let options = unsafe { &*options };
        let ipv6 = options.Flags & u64::from(DNS_SETTING_IPV6) != 0;
        if ipv6 && FAIL_V6.get() {
            return 5;
        }
        let mut len = 0;
        while unsafe { *options.NameServer.add(len) } != 0 {
            len += 1;
        }
        let value = unsafe { std::slice::from_raw_parts(options.NameServer, len) };
        SERVERS.with_borrow_mut(|values| values[ipv6 as usize] = String::from_utf16_lossy(value));
        0
    }

    #[test]
    fn restores_static_and_automatic_dns_after_stop_and_partial_failure() {
        let original = ["9.9.9.9,1.1.1.1".to_owned(), String::new()];
        SERVERS.set(original.clone());
        let adapter = Adapter {
            index: 1,
            guid: GUID::default(),
            registry_id: "test".into(),
        };
        let apply = || {
            SystemDns {
                set_dns: write,
                read_static: read,
                changed: Vec::new(),
            }
            .apply(vec![adapter.clone()])
        };
        let guard = apply().unwrap();
        assert_eq!(read("", false).unwrap(), "127.0.0.1");
        assert_eq!(read("", true).unwrap(), "::1");
        drop(guard);
        SERVERS.with_borrow(|values| assert_eq!(values, &original));
        FAIL_V6.set(true);
        assert!(apply().is_err());
        SERVERS.with_borrow(|values| assert_eq!(values, &original));
    }
}
