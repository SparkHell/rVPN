import { expect, test } from '@playwright/test'

const config = {
  server_address: 'wss://vpn.example.com/api/v1/ws',
  sni_hostname: null,
  tls_fingerprint: 'chrome',
  server_public_key: null,
  identity_key_file: './identity.key',
  prekey_bundle: './prekey-bundle.json',
  data_dir: './data',
  server: [],
  routing: {},
  socks5: {
    listen_address: '127.0.0.1:1080',
    auth_enabled: false,
    auth_username: null,
    auth_password: null,
    mode: null,
    multiplex: false,
    udp_associate: true,
    pool_size: 4,
    pool_max: 8,
    max_flows_per_conn: 100,
    rotate_after_secs: 3600,
    rotate_after_mb: 256,
    rotation_jitter: 0.1,
    mux_path: '',
  },
  http_proxy: {
    enabled: true,
    listen_address: '127.0.0.1:1088',
    auth_enabled: false,
    auth_username: null,
    auth_password: null,
    multiplex: false,
    mux_path: '',
  },
  dns_proxy: {
    enabled: true,
    takeover_system_dns: false,
    listen_address: '127.0.0.1:53',
    nameservers: ['https://1.1.1.1/dns-query', '223.5.5.5:53'],
  },
  network: {
    ipv6_enabled: true,
    prefer_ipv4: true,
    dns_cache_enabled: true,
    dns_cache_ttl: 14400,
    dns_cache_size: 1000,
    dns_servers: [],
    ech_mode: 'off',
  },
  split_tunnel: {
    enabled: true,
    builtinBypassCountries: ['CN'],
    blockAds: true,
    gfwlistEnabled: true,
    bypassNetworksFile: null,
    bypassDomainsFile: null,
    countryDomainsFile: null,
    tunnelNetworksFile: null,
    tunnelDomainsFile: null,
    autoReloadInterval: 86400,
    adBlockFile: null,
    bypassNetworks: [],
    countryIpsFile: null,
  },
  tun: {
    enabled: false,
    interface_name: null,
    dns_servers: ['1.1.1.1'],
    routes: ['0.0.0.0/0'],
    mtu: 1420,
  },
  server_identity: {
    fingerprint: null,
    trust_on_first_use: true,
    known_hosts_file: 'known_hosts.json',
    strict: true,
    strict_mode: false,
  },
  logging: { file_enabled: true, level: 'info', max_files: 7, directory: null },
  performance: {
    worker_threads: 4,
    crypto_worker_count: 4,
    recv_buffer_size: 262144,
    send_buffer_size: 262144,
  },
  dashboard: {
    enabled: true,
    listen_address: '127.0.0.1:9800',
    allow_cidrs: ['127.0.0.0/8', '::1/128'],
  },
}

test.beforeEach(async ({ page }) => {
  await page.routeWebSocket('**/ws', (ws) => {
    let current = {
      config: structuredClone(config),
      revision: 'initial',
      path: 'D:\\rvpn\\client.toml',
      restart_required: false,
      version: '1.3.6',
      runtime: {
        system_dns_supported: true,
        server_address: config.server_address,
        tun: false,
        socks5: '127.0.0.1:1080',
        http_proxy: '127.0.0.1:1088',
        dns_proxy: '127.0.0.1:53',
      },
    }
    ws.send(JSON.stringify({ type: 'session', data: current }))
    ws.send(
      JSON.stringify({
        type: 'stats',
        data: {
          uptime_secs: 3661,
          bucket_secs: 5,
          counters: {
            bytes_down: 1048576,
            bytes_up: 102400,
            tunnel_bytes: 524288,
            conns_accepted: 20,
            conns_completed: 12,
            conns_tunneled: 14,
            conns_bypassed: 5,
            conns_blocked: 1,
            conns_gfwlist: 9,
            dns_tunnel: 50,
            dns_bypass: 20,
            dns_direct: 18,
            dns_block: 5,
            dns_cache_hits: 15,
            dns_gfwlist: 30,
          },
          proxy_modes: { socks5: 'pooled', http: 'pooled', pool: { ready: 2, flows: 1 } },
          recent_proxy: [
            { id: 1, time: 1, host: 'google.com', port: 443, protocol: 'HTTP', route: '隧道', reason: '命中 GFWList', connected: true, ms: 20, mode: "pooled", reused: true, stages: [["分流", 2], ["获取隧道", 3], ["目标连接", 15]] },
            { id: 2, time: 1, host: 'baidu.com', port: 443, protocol: 'SOCKS5', route: '直连', reason: '目标地址均命中直连网段', connected: true, ms: 5 },
          ],
          buckets: [],
        },
      }),
    )
    ws.onMessage((data) => {
      const request = JSON.parse(String(data))
      if (request.method === 'rules.update') {
        ws.send(
          JSON.stringify({
            type: 'response',
            id: request.id,
            ok: true,
            data: { domains: 1234 },
          }),
        )
        return
      }
      if (request.method === 'config.save') {
        if (request.config.server_address === 'wss://reject.invalid/ws') {
          ws.send(
            JSON.stringify({
              type: 'response',
              id: request.id,
              ok: false,
              error: '配置应用失败，已恢复原配置文件：端口被占用',
            }),
          )
          return
        }
        const dashboardChanged =
          JSON.stringify(request.config.dashboard) !==
          JSON.stringify(current.config.dashboard)
        current = {
          ...current,
          config: request.config,
          revision: 'saved',
          restart_required: false,
          runtime: {
            ...current.runtime,
            ...(dashboardChanged
              ? { dashboard: request.config.dashboard }
              : {}),
          },
        }
      }
      ws.send(
        JSON.stringify({
          type: 'response',
          id: request.id,
          ok: true,
          data:
            request.method === 'config.validate' ? { valid: true } : current,
        }),
      )
    })
  })
  await page.goto('/')
  await expect(page.getByText('程序已连接', { exact: true })).toBeVisible()
})

test('overview displays live values and can navigate to all configuration sections', async ({
  page,
}) => {
  await expect(page.locator('article.metric').filter({ hasText: '已用代理流量' })).toContainText('512.0 KB')
  await expect(page.locator('.dns-summary')).toContainText('20次连接分流')
  await expect(page.locator('.dns-summary')).toContainText('本地 DNS 查询 75 次')
  await expect(page.getByText('1.0 MB', { exact: false })).toBeVisible()
  for (const label of [
    '服务器与路由',
    '本地代理',
    'DNS 与网络',
    '分流规则',
    'TUN 虚拟网卡',
    '身份验证',
    '运行与管理',
  ]) {
    await page
      .locator('nav')
      .getByRole('button', { name: label, exact: true })
      .click()
    await expect(page.locator('.page-heading h2')).toHaveText(label)
  }
})

test('edits DoH and optional log directory, validates and applies without restart', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: 'DNS 与网络', exact: true })
    .click()
  const listener = page.getByLabel('监听地址')
  const takeover = page.getByRole('switch', { name: '接管系统 DNS' })
  await page.getByRole('switch', { name: '启用 DNS 代理' }).click()
  await expect(listener).toBeDisabled()
  await expect(takeover).toBeDisabled()
  await expect(page.getByLabel('DNS 上游')).toBeEnabled()
  await page.getByRole('switch', { name: '启用 DNS 代理' }).click()
  await expect(listener).toBeEnabled()
  await takeover.click()
  await expect(listener).toBeDisabled()
  await page.getByRole('switch', { name: 'DNS 缓存' }).click()
  await expect(page.getByLabel('最大缓存条数')).toBeDisabled()
  await expect(
    page.getByRole('combobox', { name: /ECH 模式/ }),
  ).toHaveAccessibleDescription(/普通 TLS/)
  await expect(page.locator('.config-sections')).not.toContainText(
    /dns_cache_ttl|dns_servers|prefer_ipv4/,
  )
  await page
    .getByLabel('DNS 上游')
    .fill('https://dns.example.com/dns-query\n1.1.1.1:53\n')
  await page
    .locator('nav')
    .getByRole('button', { name: '运行与管理', exact: true })
    .click()
  await page.getByLabel('日志目录').fill('./logs')
  await page.getByRole('button', { name: '校验配置', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('配置校验通过')
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('配置已保存')
  await expect(page.getByRole('status')).toContainText('无需重启')
  await expect(page.locator('.restart-banner')).not.toBeVisible()
  await expect(
    page.getByRole('button', { name: '保存并应用', exact: true }),
  ).toBeDisabled()
  await page
    .locator('nav')
    .getByRole('button', { name: 'DNS 与网络', exact: true })
    .click()
  await expect(page.getByLabel('DNS 上游')).toHaveValue(
    'https://dns.example.com/dns-query\n1.1.1.1:53',
  )
  await expect(takeover).toBeChecked()
})

test('supports node and routing forms, and protects unsaved changes', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '服务器与路由', exact: true })
    .click()
  await page.getByRole('button', { name: '添加节点', exact: true }).click()
  await page.getByLabel('节点名称', { exact: false }).fill('office')
  await page
    .getByLabel('节点地址', { exact: false })
    .fill('wss://office.example/ws')
  await page.getByLabel('路由目标节点名').fill('office')
  await page.getByRole('button', { name: '添加', exact: true }).click()
  await page.getByLabel('域名规则').fill('*.example.com')
  await page.getByRole('button', { name: '重新加载', exact: true }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.getByRole('button', { name: '继续编辑', exact: true }).click()
  await expect(page.getByLabel('节点名称', { exact: false })).toHaveValue(
    'office',
  )
})

test('mobile navigation remains usable without horizontal overflow', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('button', { name: '切换导航' }).click()
  await page
    .locator('nav')
    .getByRole('button', { name: '本地代理', exact: true })
    .click()
  await expect(page.getByLabel('监听地址').first()).toBeVisible()
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true)
})

test('desktop visual reference', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1200 })
  await page.screenshot({
    path: 'test-results/control-panel-desktop.png',
    fullPage: true,
    animations: 'disabled',
  })
})

test('failed apply keeps the edited form available for correction', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '服务器与路由', exact: true })
    .click()
  await page.getByLabel('服务器地址').fill('wss://reject.invalid/ws')
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('已恢复原配置文件')
  await expect(page.getByLabel('服务器地址')).toHaveValue(
    'wss://reject.invalid/ws',
  )
  await expect(
    page.getByRole('button', { name: '保存并应用', exact: true }),
  ).toBeEnabled()
})

test('disabling the panel acknowledges success and stops reconnecting', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '运行与管理', exact: true })
    .click()
  await page.getByRole('switch', { name: '启用控制面板', exact: true }).click()
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('控制面板已关闭')
  await expect(page.getByText('面板已关闭', { exact: true })).toBeVisible()
  await expect(
    page.getByRole('button', { name: '保存并应用', exact: true }),
  ).toBeDisabled()
})

test('changing the panel address navigates after the save acknowledgement', async ({
  page,
}) => {
  await page.route('http://127.0.0.1:5174/**', (route) =>
    route.fulfill({
      contentType: 'text/html; charset=utf-8',
      body: '<h1>新控制面板地址</h1>',
    }),
  )
  await page
    .locator('nav')
    .getByRole('button', { name: '运行与管理', exact: true })
    .click()
  await page.getByLabel('监听地址').fill('127.0.0.1:5174')
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page).toHaveURL('http://127.0.0.1:5174/')
  await expect(
    page.getByRole('heading', { name: '新控制面板地址' }),
  ).toBeVisible()
})

test('split rules expose independent switches, immediate updates and DNS ratios', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '分流规则', exact: true })
    .click()
  await page.getByRole('switch', { name: 'GFWList 代理规则' }).click()
  await expect(
    page.getByRole('switch', { name: 'AdGuard 广告过滤' }),
  ).toBeChecked()
  await page.getByRole('button', { name: '更新 GFWList', exact: true }).click()
  await expect(page.getByRole('status')).toContainText(
    'GFWList 更新完成，共 1234 条',
  )
  await expect(
    page.getByRole('switch', { name: 'GFWList 代理规则' }),
  ).not.toBeChecked()
  await expect(page.locator('.dns-activity')).toContainText('95 次分流，含 75 次 DNS 查询和 20 次代理连接')
  const direct = page.locator('.dns-metrics > div').filter({ hasText: '直连命中' })
  await expect(direct).toContainText('23 次 · 24.2%')
  await expect(direct).toContainText('DNS 18 次 · 连接 5 次')
  await expect(page.locator('.dns-metrics')).toContainText('39 次 · 41.1%')
  await expect(page.getByText('就绪隧道 2 条', { exact: false })).toBeVisible()
  await page.getByText('20 ms · 复用').click()
  await expect(page.getByText('目标连接 15 ms')).toBeVisible()
  await expect(page.getByText('GFWList 命中 9 次，拦截 1 次', { exact: false })).toBeVisible()
  const httpRecord = page.getByRole('row').filter({ hasText: 'google.com:443' })
  await expect(httpRecord).toContainText(/HTTP.*隧道/)
  const socksRecord = page.getByRole('row').filter({ hasText: 'baidu.com:443' })
  await expect(socksRecord).toContainText(/SOCKS5.*直连/)
})

test('imports a PAC and lets a newer SSRL move a rule before saving', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '分流规则', exact: true })
    .click()
  const input = page.getByLabel('选择规则文件')
  const direct = page.getByRole('textbox', {
    name: '直连域名 bypassDomains',
    exact: true,
  })
  const tunnel = page.getByRole('textbox', {
    name: '隧道域名 tunnelDomains',
    exact: true,
  })
  await input.setInputFiles({
    name: 'first.pac',
    mimeType: 'application/x-ns-proxy-autoconfig',
    buffer: Buffer.from(String.raw`function FindProxyForURL(url, host) {
      if (/(?:^|\.)direct\.example\.com$/.test(host)) return "DIRECT";
    }`),
  })
  await expect(direct).toHaveValue('direct.example.com')
  await input.setInputFiles({
    name: 'next.ssrl',
    mimeType: 'text/plain',
    buffer: Buffer.from('[wildcard]\n@*://*.direct.example.com/*\n'),
  })
  await expect(page.getByRole('status')).toContainText('覆盖 1 条反向规则')
  await expect(direct).toHaveValue('')
  await expect(tunnel).toHaveValue('direct.example.com')
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('配置已保存')
  await page.setViewportSize({ width: 390, height: 844 })
  await page
    .getByRole('button', { name: '导入规则文件' })
    .scrollIntoViewIfNeeded()
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true)
})

test('maps policies from V2Ray and Shadowrocket before merging their rules', async ({
  page,
}) => {
  await page
    .locator('nav')
    .getByRole('button', { name: '分流规则', exact: true })
    .click()
  const input = page.getByLabel('选择规则文件')
  await input.setInputFiles({
    name: 'v2ray.json',
    mimeType: 'application/json',
    buffer: Buffer.from(
      JSON.stringify({
        routing: {
          rules: [
            {
              type: 'field',
              domain: ['domain:example.com'],
              outboundTag: 'local-lane',
            },
          ],
        },
      }),
    ),
  })
  await expect(
    page.getByRole('heading', { name: '映射出站策略' }),
  ).toBeVisible()
  await page.getByLabel('local-lane').selectOption('direct')
  await page.getByRole('button', { name: '加入草稿' }).click()
  await expect(
    page.getByRole('textbox', { name: '直连域名 bypassDomains', exact: true }),
  ).toHaveValue('example.com')
  await input.setInputFiles({
    name: 'shadowrocket.conf',
    mimeType: 'text/plain',
    buffer: Buffer.from(
      '[Rule]\nDOMAIN-SUFFIX,example.com,VPN Group\nIP-CIDR6,2001:db8::/32,DIRECT',
    ),
  })
  await page.getByLabel('VPN Group').selectOption('proxy')
  await page.getByRole('button', { name: '加入草稿' }).click()
  await expect(
    page.getByRole('textbox', { name: '隧道域名 tunnelDomains', exact: true }),
  ).toHaveValue('example.com')
  await expect(page.getByRole('status')).toContainText('覆盖 1 条反向规则')
  await page.getByRole('button', { name: '保存并应用', exact: true }).click()
  await expect(page.getByRole('status')).toContainText('配置已保存')
})
