use anyhow::Result;

#[derive(Clone, Debug)]
pub struct EngineSettings {
    pub download_dir: String,
    pub listen_port: u16,

    pub enable_dht: bool,
    pub enable_pex: bool,
    pub enable_lsd: bool,
    pub enable_upnp: bool,
    pub enable_nat_pmp: bool,
    pub enable_ipv6: bool,
    pub enable_utp: bool,

    pub max_connections_global: u32,
    pub max_connections_per_torrent: u32,
    pub max_active_torrents: u32,

    pub dl_limit_kib: u32, // 0 = unlimited
    pub ul_limit_kib: u32, // 0 = unlimited

    pub cache_mb: u32,
    pub write_behind: bool,
    pub preallocate: bool,
}

impl EngineSettings {
    pub fn load_default() -> Result<Self> {
        Ok(Self {
            download_dir: "Downloads".to_string(),
            listen_port: 51413,
            enable_dht: true,
            enable_pex: true,
            enable_lsd: true,
            enable_upnp: true,
            enable_nat_pmp: true,
            enable_ipv6: true,
            enable_utp: true,
            max_connections_global: 400,
            max_connections_per_torrent: 80,
            max_active_torrents: 10,
            dl_limit_kib: 0,
            ul_limit_kib: 0,
            cache_mb: 256,
            write_behind: true,
            preallocate: false,
        })
    }
}
