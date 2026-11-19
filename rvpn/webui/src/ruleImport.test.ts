import { describe, expect, it } from 'vitest'
import { importRules, prepareRuleImport } from './ruleImport'

describe('rule import', () => {
  it('imports ZeroOmega profile references and preserves first-match duplicates', () => {
    const pac = String.raw`var FindProxyForURL = function(init, profiles) {
      if (/(?:^|\.)DIRECT\.example\.com$/.test(host)) return "+node";
      if (/(?:^|\.)direct\.example\.com$/.test(host)) return "DIRECT";
      if (/^192\.0\.2\.10$/.test(host)) return "DIRECT";
      if (/^proxy\.example\.com\/path/.test(url)) return "+node";
    }('profile', {
      "+node": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";
        return "PROXY 192.0.2.1:8080";
      }
    });`
    const imported = importRules(
      pac,
      {
        bypassDomains: [' Direct.Example.Com. ', 'keep.example.com'],
        tunnelNetworks: ['192.0.2.10/32'],
      },
      'pac',
    )
    expect(imported).toMatchObject({
      rules: {
        bypassDomains: ['keep.example.com'],
        tunnelDomains: ['direct.example.com'],
        bypassNetworks: ['192.0.2.10/32'],
        tunnelNetworks: [],
      },
      imported: 2,
      replaced: 2,
      duplicates: 1,
      skipped: 1,
    })
  })

  it('lets a subsequent SSRL import replace PAC rules and keeps exceptions', () => {
    const ssrl = `; SwitchyOmega Rule List
#BEGIN
[wildcard]
@*://*.direct.example.com/*
!@*://*.direct.example.com/*
@*://198.51.100.14/*
@*://*.example.org/specific-path
[regexp]
^https://example.net/
#END`
    const result = importRules(
      ssrl,
      { tunnelDomains: ['DIRECT.example.com'] },
      'ssrl',
    )
    expect(result).toMatchObject({
      rules: {
        bypassDomains: ['direct.example.com'],
        tunnelDomains: [],
        tunnelNetworks: ['198.51.100.14/32'],
      },
      imported: 2,
      replaced: 1,
      duplicates: 1,
      skipped: 2,
    })
    expect(importRules(ssrl, result.rules, 'ssrl').rules).toEqual(result.rules)
  })
})

describe('other clients', () => {
  it('maps V2Ray outbounds and skips compound or unsupported matchers', () => {
    const config = {
      outbounds: [
        { tag: 'outside', protocol: 'vmess' },
        { tag: 'local', protocol: 'freedom' },
      ],
      routing: {
        rules: [
          {
            type: 'field',
            domain: ['domain:Example.com', 'full:example.org', 'geosite:cn'],
            outboundTag: 'outside',
          },
          {
            type: 'field',
            ip: ['2001:0db8:0000::10/48', '192.0.2.32/24'],
            outboundTag: 'local',
          },
          {
            type: 'field',
            domain: ['domain:example.net'],
            port: '443',
            outboundTag: 'outside',
          },
          {
            type: 'field',
            domain: ['domain:example.net'],
            ip: ['192.0.2.1'],
            outboundTag: 'outside',
          },
        ],
      },
    }
    const prepared = prepareRuleImport(JSON.stringify(config), 'v2ray')
    expect([...prepared.policies]).toEqual([
      ['outside', 'proxy'],
      ['local', 'direct'],
    ])
    expect(prepared.merge({ tunnelNetworks: ['2001:db8::/48'] })).toMatchObject(
      {
        imported: 3,
        replaced: 1,
        skipped: 4,
        rules: {
          tunnelDomains: ['example.com'],
          bypassNetworks: ['2001:db8::/48', '192.0.2.0/24'],
          tunnelNetworks: [],
        },
      },
    )
  })

  it('reads only the Shadowrocket rule section and accepts explicit custom policy mapping', () => {
    const file = `[General]
foo = bar
[Rule]
DOMAIN-SUFFIX,example.com,Office
IP-CIDR,198.51.100.0/24,DIRECT
IP-CIDR6,2001:db8::/32,Office
IP-CIDR,203.0.113.0/24,Office,no-resolve
DOMAIN,exact.example.com,Office
FINAL,Office
[Host]
DOMAIN-SUFFIX,ignored.example.com,Office
`
    const prepared = prepareRuleImport(file, 'shadowrocket')
    expect([...prepared.policies]).toEqual([
      ['Office', 'skip'],
      ['DIRECT', 'direct'],
    ])
    expect(
      prepared.merge(
        { bypassDomains: ['example.com'] },
        new Map([
          ['Office', 'proxy'],
          ['DIRECT', 'direct'],
        ]),
      ),
    ).toMatchObject({
      replaced: 1,
      skipped: 3,
      imported: 3,
      rules: {
        bypassDomains: [],
        tunnelDomains: ['example.com'],
        bypassNetworks: ['198.51.100.0/24'],
        tunnelNetworks: ['2001:db8::/32'],
      },
    })
  })
})
