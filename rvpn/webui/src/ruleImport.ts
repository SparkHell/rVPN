// Parse the static host rules emitted by ZeroOmega. PAC is never executed.
const fields = {
  directDomain: 'bypassDomains',
  proxyDomain: 'tunnelDomains',
  directIp: 'bypassNetworks',
  proxyIp: 'tunnelNetworks',
} as const
type FieldName = (typeof fields)[keyof typeof fields]
export type RuleFormat = 'pac' | 'ssrl' | 'shadowrocket' | 'v2ray'
export type RouteAction = 'direct' | 'proxy' | 'skip'

function hostCidr(host: string) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    const octets = host.split('.')
    if (
      octets.every(
        (octet) => Number(octet) <= 255 && String(Number(octet)) === octet,
      )
    )
      return host + '/32'
  }
  if (host.includes(':') && /^[\da-f:.]+$/i.test(host)) {
    try {
      return new URL('http://[' + host + ']').hostname.slice(1, -1) + '/128'
    } catch {
      return undefined
    }
  }
}

function networkCidr(value: string) {
  const [address, prefix, extra] = value.trim().split('/')
  const host = hostCidr(address)
  if (
    !host ||
    extra !== undefined ||
    (prefix !== undefined && !/^\d+$/.test(prefix))
  )
    return
  const [normalized, maxPrefix] = host.split('/')
  const width = Number(maxPrefix)
  const bits = prefix === undefined ? width : Number(prefix)
  if (bits > width) return
  if (width === 32) {
    const number = normalized
      .split('.')
      .reduce((total, octet) => total * 256 + Number(octet), 0)
    const network =
      bits === 0 ? 0 : (number & (0xffffffff << (32 - bits))) >>> 0
    return (
      [24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join('.') +
      '/' +
      bits
    )
  }
  const [left, right] = normalized.split('::')
  const leading = left ? left.split(':') : []
  const trailing = right ? right.split(':') : []
  const groups =
    right === undefined
      ? leading
      : [
          ...leading,
          ...Array<string>(8 - leading.length - trailing.length).fill('0'),
          ...trailing,
        ]
  const addressBits = BigInt(
    '0x' + groups.map((group) => group.padStart(4, '0')).join(''),
  )
  const hostBits = BigInt(128 - bits)
  const masked = ((addressBits >> hostBits) << hostBits)
    .toString(16)
    .padStart(32, '0')
  const network = masked.match(/.{4}/g)!.join(':')
  return new URL('http://[' + network + ']').hostname.slice(1, -1) + '/' + bits
}

function keyFor(value: string, network: boolean) {
  const normalized = value.trim().toLowerCase().replace(/\.$/, '')
  if (!network) return normalized
  return networkCidr(normalized) ?? normalized
}

function action(result: string) {
  if (/^DIRECT$/i.test(result)) return 'direct'
  if (/^(?:PROXY|HTTPS?|SOCKS[45]?)\s+\S+/i.test(result)) return 'proxy'
}

type Entry = {
  host: string
  ip?: string
  route?: 'direct' | 'proxy'
  policy?: string
}

function record(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === 'object' && !Array.isArray(value))
    return value as Record<string, unknown>
}

function domainSuffix(value: string) {
  const host = value.trim().toLowerCase().replace(/\.$/, '')
  return validDomain(host) ? host : undefined
}

function shadowrocketEntries(text: string) {
  const entries: Entry[] = []
  let section = ''
  let skipped = 0
  const hasSections = /^\s*\[.+\]\s*$/m.test(text)
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split(/\s+#/)[0].trim()
    if (!line || /^[#;]/.test(line)) continue
    if (/^\[.+\]$/.test(line)) {
      section = line.toLowerCase()
      continue
    }
    if (hasSections && section !== '[rule]') continue
    const [type, value, policy, ...options] = line
      .split(',')
      .map((value) => value.trim())
    if (!value || !policy || options.length) {
      skipped++
      continue
    }
    if (type.toUpperCase() === 'DOMAIN-SUFFIX') {
      const host = domainSuffix(value)
      if (host) {
        entries.push({ host, policy })
        continue
      }
    }
    if (['IP-CIDR', 'IP-CIDR6'].includes(type.toUpperCase())) {
      const ip = networkCidr(value)
      if (ip && ip.includes(':') === (type.toUpperCase() === 'IP-CIDR6')) {
        entries.push({ host: value, ip, policy })
        continue
      }
    }
    skipped++
  }
  return { entries, skipped }
}

function v2rayEntries(text: string) {
  let parsed: unknown
  try {
    parsed = JSON.parse(text.replace(/^\uFEFF/, ''))
  } catch {
    throw new Error('请选择有效的 V2Ray 路由 JSON 文件。')
  }
  const root = record(parsed)
  const rules = Array.isArray(parsed)
    ? parsed
    : (record(root?.routing)?.rules ?? root?.rules)
  if (!Array.isArray(rules)) throw new Error('找不到 V2Ray 的 routing.rules。')
  const entries: Entry[] = []
  const defaults = new Map<string, RouteAction>()
  if (Array.isArray(root?.outbounds)) {
    for (const value of root.outbounds) {
      const outbound = record(value)
      if (typeof outbound?.tag === 'string') {
        const protocol = String(outbound.protocol).toLowerCase()
        const route =
          protocol === 'freedom'
            ? 'direct'
            : [
                  'vmess',
                  'vless',
                  'shadowsocks',
                  'trojan',
                  'socks',
                  'http',
                  'wireguard',
                ].includes(protocol)
              ? 'proxy'
              : 'skip'
        defaults.set(outbound.tag, route)
      }
    }
  }
  let skipped = 0
  const supportedKeys = new Set([
    'type',
    'domain',
    'ip',
    'outboundTag',
    'remarks',
    'enabled',
  ])
  for (const value of rules) {
    const rule = record(value)
    if (
      !rule ||
      rule.enabled === false ||
      typeof rule.outboundTag !== 'string' ||
      (rule.type !== undefined && rule.type !== 'field') ||
      Object.keys(rule).some((key) => !supportedKeys.has(key)) ||
      (rule.domain !== undefined && rule.ip !== undefined)
    ) {
      skipped++
      continue
    }
    const policy = rule.outboundTag
    const domains = Array.isArray(rule.domain) ? rule.domain : []
    const ips = Array.isArray(rule.ip) ? rule.ip : []
    if (!domains.length && !ips.length) skipped++
    for (const value of domains) {
      const host =
        typeof value === 'string' &&
        value.startsWith('domain:') &&
        domainSuffix(value.slice(7))
      if (host) entries.push({ host, policy })
      else skipped++
    }
    for (const value of ips) {
      const ip = typeof value === 'string' && networkCidr(value)
      if (ip) entries.push({ host: ip, ip, policy })
      else skipped++
    }
  }
  return { entries, skipped, defaults }
}

function validDomain(host: string) {
  return (
    host.length <= 253 &&
    host.includes('.') &&
    !/^[\d.]+$/.test(host) &&
    host
      .split('.')
      .every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label))
  )
}

function pacEntries(text: string) {
  if (!/\bFindProxyForURL\b/.test(text))
    throw new Error('文件中找不到 FindProxyForURL。请选择 PAC 文件。')
  const profiles = new Map<string, ReturnType<typeof action>>()
  const inlineProfiles = /^\s*["'](\+[^"']+)["']\s*:\s*["']([^"']+)["']/gm
  for (const [, name, result] of text.matchAll(inlineProfiles))
    profiles.set(name, action(result))

  const constantProfiles =
    /^\s*["'](\+[^"']+)["']\s*:\s*function\s*\([^)]*\)\s*\{([^{}]*)\}/gm
  const localGuard = String.raw`if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";`
  for (const [, name, body] of text.matchAll(constantProfiles)) {
    const result = /^\s*return\s+["']([^"']+)["']\s*;?\s*$/.exec(
      body
        .trim()
        .replace(/^["']use strict["'];\s*/, '')
        .replace(localGuard, ''),
    )
    if (result) profiles.set(name, action(result[1]))
  }

  const entries: Entry[] = []
  let skipped = 0
  const conditions = /^\s*if\s*\(.*?\)\s*return\s+["']([^"']+)["']\s*;/gm
  for (const match of text.replaceAll(localGuard, '').matchAll(conditions)) {
    const route = action(match[1]) ?? profiles.get(match[1])
    const predicate = /^\s*if\s*\(\s*\/(.+)\/\.test\(host\)\s*\)/.exec(match[0])
    const pattern = predicate?.[1]
    const suffixPrefix = '(?:^|\\.)'
    if (!route || !pattern?.endsWith('$')) {
      skipped++
      continue
    }
    const suffix = pattern.startsWith(suffixPrefix)
    const prefix = suffix ? suffixPrefix : '^'
    if (!pattern.startsWith(prefix)) {
      skipped++
      continue
    }
    const literal = pattern.slice(prefix.length, -1)
    if (!/^[\da-z:-]+(?:\\\.[\da-z:-]+)*$/i.test(literal)) {
      skipped++
      continue
    }
    const host = literal.replaceAll('\\.', '.').toLowerCase()
    const ip = hostCidr(host)
    if (suffix ? !validDomain(host) || !!ip : !ip) {
      skipped++
      continue
    }
    entries.push({ host, ip, route })
  }
  return { entries, skipped }
}

function ssrlEntries(text: string) {
  const direct: Entry[] = []
  const proxy: Entry[] = []
  let section = ''
  let skipped = 0
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || /^[;#]/.test(line)) continue
    if (/^\[.*\]$/.test(line)) {
      section = line.toLowerCase()
      continue
    }
    const match =
      section === '[wildcard]' &&
      /^(!?)@\*:\/\/(\*\.)?([a-z\d.:[\]-]+)\/\*$/i.exec(line)
    const host = match ? match[3].toLowerCase() : ''
    const ip = hostCidr(host.replace(/^\[|\]$/g, ''))
    if (!match || (match[2] ? !validDomain(host) : !ip)) {
      skipped++
      continue
    }
    if (match[1]) direct.push({ host, ip, route: 'direct' })
    else proxy.push({ host, ip, route: 'proxy' })
  }
  return { entries: [...direct, ...proxy], skipped }
}

export function prepareRuleImport(text: string, format: RuleFormat) {
  const { entries, skipped, defaults } =
    format === 'v2ray'
      ? v2rayEntries(text)
      : {
          ...(format === 'shadowrocket'
            ? shadowrocketEntries(text)
            : format === 'ssrl'
              ? ssrlEntries(text)
              : pacEntries(text)),
          defaults: new Map<string, RouteAction>(),
        }
  if (!entries.length)
    throw new Error('没有找到可导入的域名后缀或 IP 网段规则。')

  const policies = new Map<string, RouteAction>()
  for (const { policy } of entries) {
    if (policy === undefined) continue
    const standard = policy.toLowerCase()
    policies.set(
      policy,
      defaults.get(policy) ??
        (standard === 'direct' || standard === 'proxy' ? standard : 'skip'),
    )
  }

  function merge(
    existing: Record<string, unknown>,
    choices: ReadonlyMap<string, RouteAction> = policies,
  ) {
    const lists = new Map<FieldName, Map<string, string>>()
    for (const field of Object.values(fields)) {
      const networks = field.endsWith('Networks')
      const values = Array.isArray(existing[field]) ? existing[field] : []
      lists.set(
        field,
        new Map(
          values
            .filter(
              (value): value is string =>
                typeof value === 'string' && !!value.trim(),
            )
            .map((value) => [keyFor(value, networks), value]),
        ),
      )
    }

    const seen = new Set<string>()
    let imported = 0
    let replaced = 0
    let duplicates = 0
    let skippedByPolicy = 0
    for (const entry of entries) {
      const { host, ip, policy } = entry
      const key = ip ?? host
      // The first matching rule for a target wins within one file.
      if (seen.has(key)) {
        duplicates++
        continue
      }
      seen.add(key)
      const route = policy === undefined ? entry.route : choices.get(policy)
      if (!route || route === 'skip') {
        skippedByPolicy++
        continue
      }
      const destination =
        fields[
          ip
            ? route === 'direct'
              ? 'directIp'
              : 'proxyIp'
            : route === 'direct'
              ? 'directDomain'
              : 'proxyDomain'
        ]
      const opposite =
        fields[
          ip
            ? route === 'direct'
              ? 'proxyIp'
              : 'directIp'
            : route === 'direct'
              ? 'proxyDomain'
              : 'directDomain'
        ]
      const previous = lists.get(opposite)!.delete(key)
      if (previous) replaced++
      if (!previous && lists.get(destination)!.has(key)) {
        duplicates++
        continue
      }
      lists.get(destination)!.set(key, key)
      imported++
    }

    return {
      rules: Object.fromEntries(
        Array.from(lists, ([field, values]) => [
          field,
          Array.from(values.values()),
        ]),
      ),
      imported,
      replaced,
      duplicates,
      skipped: skipped + skippedByPolicy,
    }
  }
  return { policies, merge }
}

export function importRules(
  text: string,
  existing: Record<string, unknown>,
  format: RuleFormat,
) {
  return prepareRuleImport(text, format).merge(existing)
}
