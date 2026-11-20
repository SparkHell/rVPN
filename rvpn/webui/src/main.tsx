import React, { useEffect, useId, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  ExternalLink,
  Globe2,
  Layers3,
  LayoutDashboard,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Route,
  Save,
  Search,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Wifi,
  X,
} from 'lucide-react'
import '@fontsource/inter/latin-600.css'
import '@fontsource/inter/latin-800.css'
import {
  bytes,
  clean,
  dashboardUrl,
  hints,
  labels,
  options,
  sections,
  setPath,
  uptime,
} from './model'
import type { Config, Session, Stats } from './model'
import { useControl } from './useControl'
import { prepareRuleImport } from './ruleImport'
import type { RouteAction, RuleFormat } from './ruleImport'
import './style.css'

const icons = {
  globe: Globe2,
  network: Network,
  radio: Radio,
  route: Route,
  layers: Layers3,
  shield: ShieldCheck,
  settings: Settings2,
}

const hiddenNetworkFields = new Set([
  'dns_cache_ttl',
  'dns_servers',
  'prefer_ipv4',
])

const fieldOrder: Record<string, string[]> = {
  dns_proxy: ['enabled', 'listen_address', 'nameservers'],
  network: [
    'dns_cache_enabled',
    'dns_cache_size',
    'ipv6_enabled',
    'ech_mode',
  ],
  socks5: [
    'listen_address',
    'auth_enabled',
    'auth_username',
    'auth_password',
    'udp_associate',
    'mode',
    'multiplex',
    'mux_path',
  ],
  http_proxy: [
    'enabled',
    'listen_address',
    'auth_enabled',
    'auth_username',
    'auth_password',
    'multiplex',
    'mux_path',
  ],
  logging: ['file_enabled', 'directory', 'max_files', 'level'],
  dashboard: ['enabled', 'listen_address', 'allow_cidrs'],
  split_tunnel: ['enabled', 'blockAds', 'adBlockFile', 'gfwlistEnabled'],
  tun: ['enabled', 'interface_name', 'mtu', 'routes', 'dns_servers'],
}

function fieldRank(section: string, name: string) {
  const index = fieldOrder[section]?.indexOf(name) ?? -1
  return index < 0 ? Infinity : index
}

function fieldDisabled(section: string, name: string, settings: Config) {
  if (name === 'enabled') return false
  if (
    settings.enabled === false &&
    !(section === 'dns_proxy' && name === 'nameservers')
  )
    return true
  if (name === 'auth_username' || name === 'auth_password')
    return settings.auth_enabled === false
  if (name === 'dns_cache_size') return settings.dns_cache_enabled === false
  if (section === 'logging' && ['directory', 'max_files'].includes(name))
    return settings.file_enabled === false
  if (section === 'split_tunnel' && name === 'adBlockFile')
    return settings.blockAds === false
  if (section === 'socks5') {
    if (name === 'multiplex') return Boolean(settings.mode)
    if (
      [
        'pool_size',
        'pool_max',
        'max_flows_per_conn',
        'rotate_after_secs',
        'rotate_after_mb',
        'rotation_jitter',
      ].includes(name)
    )
      return settings.mode !== 'pooled'
  }
  if (section === 'socks5' && name === 'mux_path')
    return (
      (settings.mode || (settings.multiplex ? 'multiplex' : 'legacy')) ===
      'legacy'
    )
  return false
}

function Field({
  name,
  value,
  onChange,
  disabled = false,
  section,
}: {
  disabled?: boolean
  section?: string
  name: string
  value: unknown
  onChange: (value: unknown) => void
}) {
  const id = useId()
  const caption =
    name === 'enabled' && section
      ? '启用' +
        (/^[A-Z]/.test(labels[section] || '') ? ' ' : '') +
        (labels[section] || section)
      : labels[name] || name
  const switchHint = hints[name]
  if (typeof value === 'boolean')
    return (
      <div className="field switch-field" data-disabled={disabled || undefined}>
        <label htmlFor={id}>
          <strong>{caption}</strong>

          {switchHint && (
            <small className="field-hint" id={`${id}-hint`}>
              {switchHint}
            </small>
          )}
        </label>
        <button
          id={id}
          disabled={disabled}
          type="button"
          role="switch"
          aria-label={caption}
          aria-checked={value}
          aria-describedby={switchHint ? `${id}-hint` : undefined}
          className={`switch ${value ? 'on' : ''}`}
          onClick={() => onChange(!value)}
        >
          <i />
        </button>
      </div>
    )
  if (value && typeof value === 'object' && !Array.isArray(value))
    return (
      <fieldset className="nested" disabled={disabled}>
        <legend>{caption}</legend>
        <div className="fields">
          {Object.entries(value).map(([key, v]) => (
            <Field
              key={key}
              name={key}
              value={v}
              onChange={(next) => onChange({ ...value, [key]: next })}
            />
          ))}
        </div>
      </fieldset>
    )
  const nullable =
    value === null ||
    [
      'sni_hostname',
      'server_public_key',
      'prekey_bundle',
      'auth_username',
      'auth_password',
      'interface_name',
      'fingerprint',
      'directory',
      'bypassNetworksFile',
      'bypassDomainsFile',
      'countryDomainsFile',
      'tunnelNetworksFile',
      'tunnelDomainsFile',
      'adBlockFile',
      'countryIpsFile',
    ].includes(name)
  const list = Array.isArray(value)
  return (
    <div
      className={`field ${list || name === 'listen_address' ? 'wide' : ''}`}
      data-disabled={disabled || undefined}
    >
      <label htmlFor={id}>
        {caption}
        <small>{name}</small>
      </label>
      {options[name] ? (
        <select
          aria-description={switchHint}
          id={id}
          disabled={disabled}
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value || null)}
        >
          {options[name].map((option) => (
            <option key={option} value={option}>
              {option || '自动 / 使用兼容设置'}
            </option>
          ))}
        </select>
      ) : list ? (
        <textarea
          id={id}
          disabled={disabled}
          rows={Math.min(6, Math.max(3, value.length + 1))}
          placeholder="每行一条"
          value={value.join('\n')}
          onChange={(e) => onChange(e.target.value.split('\n'))}
        />
      ) : (
        <input
          id={id}
          disabled={disabled}
          type={
            typeof value === 'number'
              ? 'number'
              : name.includes('password')
                ? 'password'
                : 'text'
          }
          step={
            name === 'rotation_jitter'
              ? '0.01'
              : typeof value === 'number'
                ? '1'
                : undefined
          }
          value={String(value ?? '')}
          placeholder={nullable ? '未设置（可选）' : undefined}
          autoComplete="off"
          onChange={(e) =>
            onChange(
              typeof value === 'number'
                ? e.target.value === ''
                  ? 0
                  : Number(e.target.value)
                : e.target.value || (nullable ? null : ''),
            )
          }
        />
      )}
      {hints[name] && <p className="field-hint">{hints[name]}</p>}
      {nullable && <span className="optional">可选</span>}
    </div>
  )
}

function ServerEditor({
  value,
  onChange,
}: {
  value: unknown[]
  onChange: (value: unknown[]) => void
}) {
  return (
    <div className="wide">
      <div className="editor-toolbar">
        <span>
          附加服务器 <em>{value.length}</em>
        </span>
        <button
          className="button secondary small"
          onClick={() =>
            onChange([
              ...value,
              {
                name: '',
                address: 'wss://',
                prekey_bundle: '',
                sni_hostname: null,
                fingerprint: null,
              },
            ])
          }
        >
          <Plus size={14} />
          添加节点
        </button>
      </div>
      {value.length === 0 && (
        <div className="empty-row">
          当前使用主服务器。添加节点后，可按域名或 IP 分配流量。
        </div>
      )}
      {value.map((entry, index) => (
        <div className="entry" key={index}>
          <div className="entry-heading">
            <span>节点 {String(index + 1).padStart(2, '0')}</span>
            <button
              className="icon-button"
              aria-label={`移除节点 ${index + 1}`}
              onClick={() => onChange(value.filter((_, i) => i !== index))}
            >
              <X size={16} />
            </button>
          </div>
          <div className="fields">
            {Object.entries(entry as Config).map(([name, v]) => (
              <Field
                key={name}
                name={name}
                value={v}
                onChange={(next) =>
                  onChange(
                    value.map((item, i) =>
                      i === index
                        ? { ...(item as Config), [name]: next }
                        : item,
                    ),
                  )
                }
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function RoutingEditor({
  value,
  onChange,
}: {
  value: Config
  onChange: (value: Config) => void
}) {
  const [name, setName] = useState('')
  return (
    <div className="wide">
      <div className="editor-toolbar">
        <span>按服务器分配路由</span>
        <div className="add-rule">
          <input
            aria-label="路由目标节点名"
            placeholder="目标节点名 / default"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <button
            className="button secondary small"
            disabled={!name.trim() || name.trim() in value}
            onClick={() => {
              onChange({ ...value, [name.trim()]: { domains: [], ips: [] } })
              setName('')
            }}
          >
            <Plus size={14} />
            添加
          </button>
        </div>
      </div>
      {!Object.keys(value).length && (
        <div className="empty-row">未匹配规则的连接使用主服务器。</div>
      )}
      {Object.entries(value).map(([key, rule]) => (
        <div className="entry" key={key}>
          <div className="entry-heading">
            <span>{key}</span>
            <button
              className="icon-button"
              aria-label={`移除路由 ${key}`}
              onClick={() =>
                onChange(
                  Object.fromEntries(
                    Object.entries(value).filter(([k]) => k !== key),
                  ),
                )
              }
            >
              <X size={16} />
            </button>
          </div>
          <div className="fields">
            {Object.entries(rule as Config).map(([field, v]) => (
              <Field
                key={field}
                name={field}
                value={v}
                onChange={(next) =>
                  onChange({
                    ...value,
                    [key]: { ...(rule as Config), [field]: next },
                  })
                }
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function TrafficChart({ stats }: { stats: Stats | null }) {
  const buckets = stats?.buckets.slice(-60) || []
  const maximum = Math.max(
    1,
    ...buckets.flatMap((b) => [b.bytes_up, b.bytes_down]),
  )
  const path = (key: 'bytes_up' | 'bytes_down') =>
    buckets
      .map(
        (b, i) =>
          `${i === 0 ? 'M' : 'L'}${((i / Math.max(1, buckets.length - 1)) * 800).toFixed(1)},${(150 - (b[key] / maximum) * 125).toFixed(1)}`,
      )
      .join(' ')
  return (
    <div className="traffic-chart">
      <div className="chart-axis">
        <span>{bytes(maximum / 5)}/s</span>
        <span>{bytes(maximum / 10)}/s</span>
        <span>0 B/s</span>
      </div>
      <svg
        role="img"
        aria-label="最近五分钟上传和下载流量"
        viewBox="0 0 800 170"
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop stopColor="#00b24b" stopOpacity=".22" />
            <stop offset="1" stopColor="#00b24b" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[25, 87, 150].map((y) => (
          <line
            key={y}
            x1="0"
            x2="800"
            y1={y}
            y2={y}
            stroke="#34363b"
            strokeDasharray="4 6"
          />
        ))}
        {buckets.length > 1 && (
          <>
            <path
              d={`${path('bytes_down')} L800,170 L0,170 Z`}
              fill="url(#trafficFill)"
            />
            <path
              d={path('bytes_down')}
              fill="none"
              stroke="#00b24b"
              strokeWidth="2.5"
            />
            <path
              d={path('bytes_up')}
              fill="none"
              stroke="#0075ff"
              strokeWidth="2"
            />
          </>
        )}
        {buckets.length < 2 && (
          <text x="400" y="90" textAnchor="middle" fill="#9aa1b1" fontSize="14">
            等待流量采样，建立连接后自动更新
          </text>
        )}
      </svg>
      <div className="chart-times">
        <span>5 分钟前</span>
        <span>现在</span>
      </div>
    </div>
  )
}

function Overview({
  session,
  stats,
  connected,
  navigate,
}: {
  session: Session | null
  stats: Stats | null
  connected: boolean
  navigate: (page: string) => void
}) {
  const counters = stats?.counters || {}
  const active = Math.max(
    0,
    (counters.conns_accepted || 0) - (counters.conns_completed || 0),
  )
  const latest = stats?.buckets.at(-1)
  return (
    <>
      <section className="hero">
        <div>
          <div className="eyebrow">
            <span className={`dot ${connected ? 'live' : ''}`} />
            {connected ? '客户端已连接' : '客户端未连接'}
          </div>
          <h1>
            你的网络，
            <br />
            由你掌控<span>。</span>
          </h1>
          <p>连接状态、实时流量与每一条规则，尽在此处。</p>
          <button
            className="button primary"
            onClick={() => navigate('connection')}
          >
            管理连接
            <ChevronRight size={16} />
          </button>
        </div>
        <div className="hero-network" aria-hidden="true">
          <div className="orbit orbit-one" />
          <div className="orbit orbit-two" />
          <div className="orbit orbit-three" />
          <div className="network-center">
            <ShieldCheck size={47} strokeWidth={1.5} />
          </div>
          <div className="network-node node-one">
            <Globe2 size={20} />
          </div>
          <div className="network-node node-two">
            <Wifi size={20} />
          </div>
          <div className="network-node node-three">
            <Layers3 size={19} />
          </div>
          <span className="network-tag">DOUBLE RATCHET ENCRYPTION</span>
        </div>
        <div className="hero-status">
          <span>当前网络模式</span>
          <strong>
            {session?.runtime.tun ? 'TUN 网络' : 'SOCKS5 代理'}
          </strong>
          <span className="live-label">
            <i />
            {session?.runtime.tun
              ? stats?.tun_ready ? 'TUN 已连接' : 'TUN 等待接管'
              : '端到端加密'}
          </span>
        </div>
      </section>
      <div className="metrics-grid">
        {[
          {
            label: '实时下载',
            value: `${bytes((latest?.bytes_down || 0) / 5)}`,
            unit: '/s',
            icon: ArrowDownLeft,
            color: 'green',
            sub: `累计 ${bytes(counters.bytes_down)}`,
          },
          {
            label: '实时上传',
            value: bytes((latest?.bytes_up || 0) / 5),
            unit: '/s',
            icon: ArrowUpRight,
            color: 'blue',
            sub: `累计 ${bytes(counters.bytes_up)}`,
          },
          {
            label: '活跃连接',
            value: String(active),
            unit: '',
            icon: Network,
            color: 'blue',
            sub: `已处理 ${counters.conns_accepted || 0} 个连接`,
          },
          {
            label: '运行时长',
            value: uptime(stats?.uptime_secs),
            unit: '',
            icon: Clock3,
            color: 'green',
            sub: '客户端进程在线时间',
          },
        ].map((metric) => (
          <article className="metric" key={metric.label}>
            <div className="metric-top">
              <span>{metric.label}</span>
              <metric.icon size={18} className={metric.color} />
            </div>
            <strong>
              {metric.value}
              <small>{metric.unit}</small>
            </strong>
            <p>{metric.sub}</p>
          </article>
        ))}
      </div>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>流量趋势</h2>
            <p>最近 5 分钟 · 每 5 秒采样</p>
          </div>
          <div className="legend">
            <span>
              <i className="green-bg" />
              下载
            </span>
            <span>
              <i className="blue-bg" />
              上传
            </span>
            <b>LIVE</b>
          </div>
        </div>
        <TrafficChart stats={stats} />
      </section>
      <div className="overview-grid">
        <section className="panel connection-card">
          <div className="panel-heading">
            <h2>当前连接</h2>
            <Globe2 size={18} />
          </div>
          <div className="server-row">
            <div className="server-icon">
              <Globe2 size={22} />
            </div>
            <div>
              <strong>主服务器</strong>
              <code>{session?.runtime.server_address || '等待客户端信息'}</code>
            </div>
          </div>
          <div className="endpoint-row">
            <span>SOCKS5</span>
            <code>{session?.runtime.socks5 || '—'}</code>
          </div>
          <div className="endpoint-row">
            <span>HTTP 代理</span>
            <code>{session?.runtime.http_proxy || '—'}</code>
          </div>
          <button className="text-link" onClick={() => navigate('connection')}>
            打开连接配置
            <ArrowUpRight size={14} />
          </button>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>DNS 与分流</h2>
            <ShieldCheck size={18} />
          </div>
          <div className="dns-summary">
            <strong>
              {(counters.dns_tunnel || 0) +
                (counters.dns_bypass || 0) +
                (counters.dns_block || 0)}
              <span>次 DNS 查询</span>
            </strong>
            <span>实时累计</span>
          </div>
          <div className="dns-bars">
            {[
              {
                name: '隧道解析',
                value: counters.dns_tunnel || 0,
                color: 'blue-bg',
              },
              {
                name: '直连解析',
                value: counters.dns_bypass || 0,
                color: 'green-bg',
              },
              {
                name: '已拦截',
                value: counters.dns_block || 0,
                color: 'muted-bg',
              },
            ].map((item) => (
              <div key={item.name}>
                <span>
                  <i className={item.color} />
                  {item.name}
                </span>
                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
          <button className="text-link" onClick={() => navigate('split')}>
            查看分流规则与查询统计
            <ArrowUpRight size={14} />
          </button>
        </section>
      </div>
      <div className="quick-heading">
        <h2>按你的方式连接</h2>
        <span>所有配置，集中管理</span>
      </div>
      <div className="quick-grid">
        {sections.slice(1, 5).map((section) => {
          const Icon = icons[section.icon]
          return (
            <button
              className="quick-card"
              key={section.id}
              onClick={() => navigate(section.id)}
            >
              <Icon size={22} />
              <strong>{section.title}</strong>
              <span>{section.sub}</span>
              <ChevronRight size={16} />
            </button>
          )
        })}
      </div>
    </>
  )
}

function RouteInspection({
  request,
  connected,
}: {
  request: (
    method: string,
    payload: Record<string, unknown>,
  ) => Promise<unknown>
  connected: boolean
}) {
  const [target, setTarget] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{
    target: string
    connection: string
    reason: string
    dnsReason?: string
    dnsEnabled?: boolean
    a?: string
    aaaa?: string
    other?: string
    addresses?: string[]
  }>()
  return (
    <section className="panel config-panel route-inspection">
      <div className="panel-heading">
        <div>
          <h2>检查分流路径</h2>
          <p>
            使用已应用的配置检查连接和 DNS 路径。修改规则后，请先保存再检查。
          </p>
        </div>
      </div>
      <form
        className="add-rule rule-actions"
        onSubmit={async (event) => {
          event.preventDefault()
          if (busy || !target.trim()) return
          setBusy(true)
          setError('')
          setResult(undefined)
          try {
            setResult(
              (await request('rules.inspect', {
                target: target.trim(),
              })) as typeof result,
            )
          } catch (error) {
            setError((error as Error).message)
          } finally {
            setBusy(false)
          }
        }}
      >
        <input
          aria-label="待检查的域名或 IP"
          placeholder="example.com 或 1.1.1.1"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
          required
        />
        <button
          className="button tertiary"
          disabled={busy || !connected || !target.trim()}
        >
          {busy ? '检查中…' : '检查路径'}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {result && (
        <dl aria-live="polite">
          <dt>目标</dt>
          <dd>{result.target}</dd>
          <dt>代理连接</dt>
          <dd>{result.connection}</dd>
          <dt>连接判定</dt>
          <dd>{result.reason}</dd>
          {result.a &&
            (result.dnsEnabled ? (
              <>
                <dt>DNS 判定</dt>
                <dd>{result.dnsReason}</dd>
                <dt>IPv4 查询（A）</dt>
                <dd>{result.a}</dd>
                <dt>IPv6 查询（AAAA）</dt>
                <dd>{result.aaaa}</dd>
                <dt>其他 DNS 记录</dt>
                <dd>{result.other}</dd>
                {!!result.addresses?.length && (
                  <>
                    <dt>本地解析地址</dt>
                    <dd>{result.addresses.join('、')}</dd>
                  </>
                )}
              </>
            ) : (
              <>
                <dt>DNS 代理</dt>
                <dd>已关闭</dd>
              </>
            ))}
        </dl>
      )}
    </section>
  )
}

function DnsActivity({ stats }: { stats: Stats | null | undefined }) {
  const counters = stats?.counters || {}
  const total =
    (counters.dns_tunnel || 0) +
    (counters.dns_bypass || 0) +
    (counters.dns_block || 0)
  const metrics = [
    ['缓存命中', counters.dns_cache_hits || 0],
    ['广告拦截', counters.dns_block || 0],
    ['GFWList 命中', counters.dns_gfwlist || 0],
  ] as const
  return (
    <section className="panel config-panel dns-activity">
      <div className="panel-heading">
        <div>
          <h2>DNS 查询统计</h2>
          <p>
            本次运行累计 {total} 次查询，当前排队 {counters.dns_queue_depth || 0}，过载拒绝 {counters.dns_overload || 0} 次。
          </p>
        </div>
      </div>
      <div className="dns-metrics">
        {metrics.map(([label, count]) => (
          <div key={label}>
            <strong>{label}</strong>
            <span>
              {count} 次 · {total ? ((100 * count) / total).toFixed(1) : '0'}%
            </span>
            <progress
              aria-label={label}
              value={count}
              max={Math.max(total, 1)}
            />
          </div>
        ))}
      </div>
      <h3>最近解析</h3>
      {stats?.recent_dns?.length ? (
        <div className="dns-query-scroll">
          <table>
            <thead>
              <tr>
                {['时间', '域名', '类型', '处理方式', '解析结果', '耗时'].map(
                  (h) => (
                    <th key={h}>{h}</th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {stats.recent_dns.map((r, index) => (
                <tr key={index}>
                  <td>{new Date(r.time * 1000).toLocaleTimeString()}</td>
                  <td>{r.domain}</td>
                  <td>{r.type}</td>
                  <td>
                    {[r.route, r.cached && '缓存', r.gfwlist && 'GFWList']
                      .filter(Boolean)
                      .join(' · ')}
                  </td>
                  <td>
                    {r.answers.length
                      ? r.answers.join('、')
                      : r.rcode === 'NoError'
                        ? '无记录'
                        : r.rcode}
                  </td>
                  <td>{r.ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>等待本地 DNS 代理接收查询。</p>
      )}
    </section>
  )
}

function ProxyActivity({ stats }: { stats: Stats | null | undefined }) {
  const records = stats?.recent_proxy
  return (
    <section className="panel config-panel">
      <h2>最近代理连接</h2>
      {records?.length ? (
        <div className="dns-query-scroll">
          <table>
            <thead>
              <tr>
                {['时间', '目标', '代理', '分流结果', '连接状态', '耗时'].map(
                  (heading) => <th key={heading}>{heading}</th>,
                )}
              </tr>
            </thead>
            <tbody>
              {records.map((entry) => (
                <tr key={entry.id}>
                  <td>{new Date(entry.time * 1000).toLocaleTimeString()}</td>
                  <td>{entry.host.includes(':') ? `[${entry.host}]` : entry.host}:{entry.port}</td>
                  <td>{entry.protocol}</td>
                  <td>{entry.route} · {entry.reason}</td>
                  <td>{entry.route === '拦截' ? '已拦截' : entry.connected ? '已连接' : '失败'}</td>
                  <td>{entry.ms} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>等待 HTTP 或 SOCKS5 代理连接。</p>
      )}
    </section>
  )
}

function App() {
  const {
    connected,
    session,
    setSession,
    stats,
    error: connectionError,
    request,
    pause,
    pausedReason,
  } = useControl()
  const ruleFile = useRef<HTMLInputElement>(null)
  const [pendingImport, setPendingImport] = useState<ReturnType<
    typeof prepareRuleImport
  > | null>(null)
  const [importChoices, setImportChoices] = useState(
    new Map<string, RouteAction>(),
  )

  const [page, setPage] = useState('overview')
  const [draft, setDraft] = useState<Config | null>(null)
  const [base, setBase] = useState<Session | null>(null)
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{
    text: string
    error?: boolean
  } | null>(null)
  const [confirmReload, setConfirmReload] = useState(false)
  const [mobile, setMobile] = useState(false)
  const dirty =
    !!draft &&
    !!base &&
    JSON.stringify(clean(draft)) !== JSON.stringify(clean(base.config))
  useEffect(() => {
    if (
      session &&
      (!base || (!dirty && JSON.stringify(session) !== JSON.stringify(base)))
    ) {
      setBase(session)
      setDraft(structuredClone(session.config))
    }
  }, [session, base, dirty])
  useEffect(() => {
    const listener = (event: BeforeUnloadEvent) => {
      if (dirty) event.preventDefault()
    }
    window.addEventListener('beforeunload', listener)
    return () => window.removeEventListener('beforeunload', listener)
  }, [dirty])
  const activeSection = sections.find((section) => section.id === page)
  const navigate = (next: string) => {
    setPage(next)
    setSearch('')
    setMobile(false)
    setNotice(null)
  }
  async function updateRules(source: 'adguard' | 'gfwlist') {
    setBusy(true)
    const name = source === 'adguard' ? 'AdGuard' : 'GFWList'
    setNotice({ text: `正在下载 ${name} 规则…` })
    try {
      const result = (await request('rules.update', { source })) as {
        domains: number
      }
      setNotice({ text: `${name} 更新完成，共 ${result.domains} 条域名规则。` })
    } catch (error) {
      setNotice({
        text: `${name} 更新失败：${(error as Error).message}`,
        error: true,
      })
    } finally {
      setBusy(false)
    }
  }
  function applyRuleImport(
    prepared: ReturnType<typeof prepareRuleImport>,
    choices?: ReadonlyMap<string, RouteAction>,
  ) {
    if (!draft) return
    const summary = prepared.merge(draft.split_tunnel as Config, choices)
    setDraft(
      setPath(draft, ['split_tunnel'], {
        ...(draft.split_tunnel as Config),
        ...summary.rules,
      }),
    )
    setPendingImport(null)
    setNotice({
      text: `已导入 ${summary.imported} 条，覆盖 ${summary.replaced} 条反向规则，忽略 ${summary.duplicates} 条重复规则，跳过 ${summary.skipped} 条。检查后点击「保存并应用」。`,
    })
  }

  async function importRuleFile(file: File) {
    try {
      if (file.size > 1024 * 1024) throw new Error('规则文件不能超过 1 MiB。')
      const formats: Record<string, RuleFormat> = {
        ssrl: 'ssrl',
        pac: 'pac',
        conf: 'shadowrocket',
        json: 'v2ray',
      }
      const format = formats[file.name.split('.').at(-1)?.toLowerCase() ?? '']
      if (!format)
        throw new Error('请选择 PAC、SSRL、小火箭 CONF 或 V2Ray JSON 文件。')
      const prepared = prepareRuleImport(await file.text(), format)
      if (prepared.policies.size > 0) {
        setImportChoices(new Map(prepared.policies))
        setPendingImport(prepared)
      } else {
        applyRuleImport(prepared)
      }
    } catch (error) {
      setNotice({ text: (error as Error).message, error: true })
    }
  }
  async function reload() {
    setBusy(true)
    try {
      const fresh = (await request('config.get')) as Session
      setSession(fresh)
      setBase(fresh)
      setDraft(structuredClone(fresh.config))
      setNotice({ text: '已加载磁盘上的最新配置' })
    } catch (error) {
      setNotice({ text: String((error as Error).message), error: true })
    } finally {
      setBusy(false)
      setConfirmReload(false)
    }
  }
  async function save(validateOnly = false) {
    if (!draft || !base) return
    setBusy(true)
    setNotice(null)
    try {
      const result = await request(
        validateOnly ? 'config.validate' : 'config.save',
        { config: clean(draft), revision: base.revision },
      )
      if (validateOnly) setNotice({ text: '配置校验通过' })
      else {
        const fresh = result as Session
        setBase(fresh)
        setSession(fresh)
        setDraft(structuredClone(fresh.config))
        setNotice({ text: '配置已保存并应用，无需重启客户端。' })
        if (fresh.runtime.dashboard) {
          const destination = dashboardUrl(
            fresh.runtime.dashboard,
            location.href,
          )
          if (destination === null) {
            pause()
            setNotice({ text: '配置已保存并应用，控制面板已关闭。' })
          } else if (fresh.access_allowed === false) {
            pause('denied')
            setNotice({
              text: '配置已应用，新的访问规则不允许当前设备继续访问面板。',
            })
          } else if (destination !== location.origin) {
            pause('moving')
            setNotice({ text: '配置已应用，正在切换到新的控制面板地址…' })
            setTimeout(() => location.assign(destination), 100)
          }
        }
      }
    } catch (error) {
      setNotice({ text: (error as Error).message, error: true })
    } finally {
      setBusy(false)
    }
  }
  const keys = activeSection?.keys || []
  const unknownKeys = draft
    ? Object.keys(draft).filter(
        (key) =>
          !sections.some((section) =>
            (section.keys as readonly string[]).includes(key),
          ),
      )
    : []
  return (
    <div className="app-shell">
      <aside className={mobile ? 'sidebar mobile-open' : 'sidebar'}>
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault()
            navigate('overview')
          }}
        >
          <span className="brand-mark">r</span>
          <strong>
            rVPN<span>CONTROL</span>
          </strong>
        </a>
        <div className="nav-caption">工作空间</div>
        <nav>
          <button
            className={page === 'overview' ? 'nav-item active' : 'nav-item'}
            onClick={() => navigate('overview')}
          >
            <LayoutDashboard size={19} />
            <span>概览</span>
            <span className="nav-live">LIVE</span>
          </button>
          <div className="nav-caption configuration-label">配置管理</div>
          {sections.map((section) => {
            const Icon = icons[section.icon]
            return (
              <button
                className={page === section.id ? 'nav-item active' : 'nav-item'}
                key={section.id}
                onClick={() => navigate(section.id)}
              >
                <Icon size={19} />
                <span>{section.title}</span>
                {page === section.id && <ChevronRight size={14} />}
              </button>
            )
          })}
          {unknownKeys.length > 0 && (
            <button
              className={page === 'other' ? 'nav-item active' : 'nav-item'}
              onClick={() => navigate('other')}
            >
              <SlidersHorizontal size={19} />
              其他配置
            </button>
          )}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-badge">
            <ShieldCheck size={18} />
            <div>
              本机控制面板<span>所有资源已内嵌</span>
            </div>
          </div>
          <div className="build-label">
            rVPN v{session?.version || '—'}
            <span>DESKTOP CLIENT</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button menu-button"
              aria-label="切换导航"
              onClick={() => setMobile(!mobile)}
            >
              <Layers3 size={20} />
            </button>
            <span>控制面板</span>
            <ChevronRight size={13} />
            <strong>
              {activeSection?.title ||
                (page === 'overview' ? '概览' : '其他配置')}
            </strong>
          </div>
          <div className="topbar-actions">
            <span
              className={`connection-indicator ${connected ? 'connected' : ''}`}
            >
              <i />
              {connected
                ? '程序已连接'
                : pausedReason === 'closed'
                  ? '面板已关闭'
                  : pausedReason === 'denied'
                    ? '访问权限已更新'
                    : pausedReason === 'moving'
                      ? '正在切换'
                      : '连接中'}
            </span>
            <span className="local-label">LOCAL</span>
            <button
              className="icon-button"
              aria-label="查看使用帮助"
              onClick={() =>
                setNotice({
                  text: '点击「保存并应用」立即生效。网络设置变更会重新建立连接；相对路径基于配置文件目录。',
                })
              }
            >
              <CircleHelp size={19} />
            </button>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <h2>
                {page === 'overview'
                  ? '网络概览'
                  : activeSection?.title || '其他配置'}
              </h2>
              <p>
                {page === 'overview'
                  ? '查看代理状态、流量与连接记录。'
                  : activeSection?.sub || '配置文件中的附加设置'}
              </p>
            </div>
            <span className="sync-label">
              <RefreshCw size={13} />
              {connected
                ? 'WebSocket 实时同步'
                : pausedReason
                  ? '已停止同步'
                  : '正在重新连接'}
            </span>
          </div>
          {(notice || connectionError) && (
            <div
              className={`notice ${notice?.error ? 'error' : ''}`}
              role={notice?.error ? 'alert' : 'status'}
            >
              <span>{notice?.text || connectionError}</span>
              <button
                className="icon-button"
                aria-label="关闭提示"
                onClick={() => setNotice(null)}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {base?.pending_changes && (
            <div className="restart-banner">
              <RefreshCw size={17} />
              <span>
                检测到配置文件的外部修改。检查设置后点击「保存并应用」更新运行配置。
              </span>
            </div>
          )}
          {page === 'overview' && stats?.last_tls && <p>最近一次 TLS 握手：{stats.last_tls}</p>}
          {stats?.runtime_error && (
            <div className="notice error" role="alert">
              <ShieldCheck size={18} />
              <span>
                VPN 已停止：{stats.runtime_error}
                。你仍可修改配置并点击「保存并应用」恢复运行。
              </span>
            </div>
          )}
          {page === 'overview' ? (
            <Overview
              session={session}
              stats={stats}
              connected={connected}
              navigate={navigate}
            />
          ) : !draft ? (
            <div className="loading-state">
              <RefreshCw size={24} className="animate-spin" />
              <h2>正在读取客户端配置</h2>
              <p>连接建立后，配置会自动显示。</p>
            </div>
          ) : (
            <>
              <div className="config-toolbar">
                <div className="search-field">
                  <Search size={17} />
                  <input
                    aria-label="搜索配置项"
                    placeholder="搜索配置名称或字段…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                  <kbd>配置</kbd>
                </div>
                <button
                  className="button tertiary"
                  disabled={!connected || busy}
                  onClick={() =>
                    dirty ? setConfirmReload(true) : void reload()
                  }
                >
                  <RefreshCw size={15} />
                  重新加载
                </button>
              </div>
              <div className="config-sections">
                {page === 'split' && !search && (
                  <>
                    <section className="panel config-panel">
                      <div className="panel-heading">
                        <div>
                          <h2>规则订阅</h2>
                          <p>
                            AdGuard 命中时拦截，GFWList 命中时连接走
                            VPN。其余域名先用本地 DNS 上游解析，再按 IP
                            分流。规则更新立即生效，开关修改需保存。
                          </p>
                        </div>
                      </div>
                      <div className="fields">
                        {['enabled', 'blockAds', 'gfwlistEnabled'].map(
                          (name) => {
                            const settings = draft.split_tunnel as
                              Config | undefined
                            if (
                              !settings ||
                              typeof settings[name] !== 'boolean'
                            )
                              return null
                            return (
                              <Field
                                key={name}
                                section="split_tunnel"
                                name={name}
                                value={settings[name]}
                                disabled={fieldDisabled(
                                  'split_tunnel',
                                  name,
                                  settings,
                                )}
                                onChange={(value) =>
                                  setDraft(
                                    setPath(
                                      draft,
                                      ['split_tunnel', name],
                                      value,
                                    ),
                                  )
                                }
                              />
                            )
                          },
                        )}
                      </div>
                      <div className="rule-actions">
                        {(['adguard', 'gfwlist'] as const).map((source) => (
                          <button
                            key={source}
                            className="button tertiary"
                            disabled={busy || !connected}
                            onClick={() => void updateRules(source)}
                          >
                            <RefreshCw size={15} />
                            更新 {source === 'adguard' ? 'AdGuard' : 'GFWList'}
                          </button>
                        ))}
                      </div>
                    </section>
                    <RouteInspection request={request} connected={connected} />
                  </>
                )}

                {(page === 'other' ? unknownKeys : keys)
                  .filter((key) => key in draft)
                  .map((key) => {
                    const value = draft[key]
                    const filter = (name: string) =>
                      !search ||
                      `${name} ${labels[name] || ''}`
                        .toLowerCase()
                        .includes(search.toLowerCase())
                    const object =
                      !!value &&
                      typeof value === 'object' &&
                      !Array.isArray(value) &&
                      key !== 'routing'
                    const entries = object
                      ? Object.entries(value)
                          .filter(
                            ([name]) =>
                              (key !== 'network' ||
                                !hiddenNetworkFields.has(name)) &&
                              (key !== 'split_tunnel' ||
                                search ||
                                ![
                                  'enabled',
                                  'blockAds',
                                  'gfwlistEnabled',
                                ].includes(name)) &&
                              (filter(key) || filter(name)),
                          )
                          .sort(
                            ([a], [b]) => fieldRank(key, a) - fieldRank(key, b),
                          )
                      : []
                    if (key === 'split_tunnel' && !search && object) {
                      const settings = value as Config
                      const directFields = [
                        'bypassDomains',
                        'tunnelDomains',
                        'bypassNetworks',
                        'tunnelNetworks',
                      ]
                      const render = ([name, fieldValue]: [
                        string,
                        unknown,
                      ]) => (
                        <Field
                          key={name}
                          name={name}
                          value={fieldValue}
                          section={key}
                          disabled={fieldDisabled(key, name, settings)}
                          onChange={(next) =>
                            setDraft(setPath(draft, [key, name], next))
                          }
                        />
                      )
                      return (
                        <section className="panel config-panel" key={key}>
                          <div className="panel-heading rule-import-heading">
                            <div>
                              <h2>自定义分流规则</h2>
                              <p>
                                每行一条，直接添加、修改或删除。域名匹配包含子域。域名规则优先于
                                IP 网段，隧道规则优先于同类直连规则。
                              </p>
                              <p>
                                支持 ZeroOmega PAC、SSRL、V2Ray JSON 和小火箭
                                CONF。同一目标以后导入的规则为准。
                              </p>
                              <p>
                                SSRL 普通规则走 VPN，例外规则直连。V2Ray
                                和小火箭可导入域名后缀与 IP
                                网段，导入后按本面板的规则优先级执行。
                              </p>
                            </div>
                            <input
                              ref={ruleFile}
                              type="file"
                              accept=".pac,.ssrl,.json,.conf"
                              hidden
                              aria-label="选择规则文件"
                              onChange={(event) => {
                                const file = event.target.files?.[0]
                                event.target.value = ''
                                if (file) void importRuleFile(file)
                              }}
                            />
                            <button
                              type="button"
                              className="button tertiary"
                              disabled={busy}
                              onClick={() => ruleFile.current?.click()}
                            >
                              导入规则文件
                            </button>
                          </div>
                          {pendingImport && (
                            <div className="rule-import-policies">
                              <h3>映射出站策略</h3>
                              <p>
                                为每个出站标签或策略组选择去向。选择跳过时，该标签的规则不会加入草稿。
                              </p>
                              <div className="fields">
                                {Array.from(
                                  importChoices,
                                  ([policy, choice]) => (
                                    <label
                                      className="rule-policy-field"
                                      key={policy}
                                    >
                                      <span>{policy}</span>
                                      <select
                                        value={choice}
                                        onChange={(event) => {
                                          const value = event.target
                                            .value as RouteAction
                                          setImportChoices((current) =>
                                            new Map(current).set(policy, value),
                                          )
                                        }}
                                      >
                                        <option value="skip">跳过</option>
                                        <option value="direct">直连</option>
                                        <option value="proxy">VPN</option>
                                      </select>
                                    </label>
                                  ),
                                )}
                              </div>
                              <div className="rule-actions">
                                <button
                                  type="button"
                                  className="button primary"
                                  onClick={() =>
                                    applyRuleImport(
                                      pendingImport,
                                      importChoices,
                                    )
                                  }
                                >
                                  加入草稿
                                </button>
                                <button
                                  type="button"
                                  className="button tertiary"
                                  onClick={() => setPendingImport(null)}
                                >
                                  取消导入
                                </button>
                              </div>
                            </div>
                          )}
                          <div className="fields">
                            {directFields.map((name) =>
                              render([name, settings[name] ?? []]),
                            )}
                          </div>
                          <details className="rule-advanced">
                            <summary>高级设置与规则文件</summary>
                            <p>
                              已有规则文件可继续使用，程序会合并文件和上方输入的规则。相对路径从配置文件所在目录计算。
                            </p>
                            <div className="fields">
                              {entries
                                .filter(
                                  ([name]) => !directFields.includes(name),
                                )
                                .map(render)}
                            </div>
                          </details>
                        </section>
                      )
                    }
                    if (search && !filter(key) && !entries.length) return null
                    return (
                      <section className="panel config-panel" key={key}>
                        <div className="panel-heading">
                          <div>
                            <h2>{labels[key] || key}</h2>
                            {object && hints[key] && <p>{hints[key]}</p>}
                          </div>
                          <SlidersHorizontal size={18} />
                        </div>
                        <div className="fields">
                          {key === 'server' ? (
                            <ServerEditor
                              value={value as unknown[]}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          ) : key === 'routing' ? (
                            <RoutingEditor
                              value={value as Config}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          ) : object ? (
                            entries.map(([name, v]) => (
                              <Field
                                key={name}
                                name={name}
                                value={v}
                                section={key}
                                disabled={fieldDisabled(
                                  key,
                                  name,
                                  value as Config,
                                )}
                                onChange={(next) =>
                                  setDraft(setPath(draft, [key, name], next))
                                }
                              />
                            ))
                          ) : (
                            <Field
                              name={key}
                              value={value}
                              onChange={(next) =>
                                setDraft(setPath(draft, [key], next))
                              }
                            />
                          )}
                        </div>
                      </section>
                    )
                  })}
                {page === 'split' && !search && (
                  <>
                    <DnsActivity stats={stats} />
                    <ProxyActivity stats={stats} />
                  </>
                )}
              </div>
              <div className="save-bar">
                <div>
                  <span className={`dot ${dirty ? 'edited' : 'live'}`} />
                  <strong>{dirty ? '有未保存的修改' : '配置已同步'}</strong>
                  <span className="save-caption">
                    网络设置变更会重新建立连接
                  </span>
                </div>
                <div>
                  <button
                    className="button tertiary"
                    disabled={!connected || busy}
                    onClick={() => void save(true)}
                  >
                    <Check size={15} />
                    校验配置
                  </button>
                  <button
                    className="button primary"
                    disabled={
                      !connected ||
                      busy ||
                      (!dirty &&
                        !base?.pending_changes &&
                        !stats?.runtime_error)
                    }
                    onClick={() => void save()}
                  >
                    {busy ? (
                      <RefreshCw size={16} className="animate-spin" />
                    ) : (
                      <Save size={16} />
                    )}
                    {busy ? '正在应用…' : '保存并应用'}
                  </button>
                </div>
              </div>
            </>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} />
              rVPN · 连接自由，始终私密
            </span>
            <span title={base?.path}>{base?.path || '等待配置路径'}</span>
          </footer>
        </main>
      </div>
      {confirmReload && (
        <div className="modal-backdrop">
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="reload-title"
            className="modal"
          >
            <h2 id="reload-title">放弃未保存的修改？</h2>
            <p>重新加载将使用磁盘上的最新配置，当前页面中的修改会被替换。</p>
            <div>
              <button
                className="button tertiary"
                onClick={() => setConfirmReload(false)}
              >
                继续编辑
              </button>
              <button className="button primary" onClick={() => void reload()}>
                重新加载
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
