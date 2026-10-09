// Writes l4_helpers.json: Dart's answers for the L4 helpers (clashProxyFor,
// unique() naming, clashSshProxies, paopaoHosts, moduleConfig,
// ScriptModule.name) over many inputs, for tests/golden_rules.rs.
//
// Not part of either build. To regenerate, copy it into
// paopao-sdk-dart/packages/paopao_proxy/test/ (and delete it afterwards):
//
//   L4_OUT=<this dir>/l4_helpers.json L4_GOLDEN=<crate>/tests/golden \
//     fvm dart test test/l4_helpers_dump.dart
import 'dart:convert';
import 'dart:io';

import 'package:paopao_proxy/paopao_proxy.dart';
import 'package:test/test.dart';

Object? _try(Object? Function() f) {
  try {
    return {'ok': jsonDecode(jsonEncode(f()))};
  } on Object catch (e) {
    return {'throws': '${e.runtimeType}'};
  }
}

void main() {
  final out = Platform.environment['L4_OUT'];
  final golden = Platform.environment['L4_GOLDEN'];
  test('dump', () {
    if (out == null || golden == null) return;
    // ---------------------------------------------------- clashProxyFor
    final outbounds = <Map<String, Object?>>[];
    for (final f in Directory('$golden/parse').listSync().whereType<File>()) {
      if (!f.path.endsWith('.json')) continue;
      final d = jsonDecode(f.readAsStringSync()) as Map;
      for (final n in (d['expected'] as Map)['nodes'] as List) {
        outbounds.add(Map<String, Object?>.from(n as Map));
      }
    }
    Map<String, Object?> n(String name, Map<String, Object?> o) => {
      'name': name,
      'outbound': o,
    };
    outbounds.addAll([
      n('ss plain', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'method': 'aes-128-gcm', 'password': 'p'}),
      n('ss no method', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1}),
      n('ss obfs', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'method': 'm', 'password': 'p', 'plugin': 'obfs-local', 'plugin_opts': 'obfs=http;obfs-host=a.com'}),
      n('ss obfs empty', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'method': 'm', 'password': 'p', 'plugin': 'obfs-local'}),
      n('ss v2ray', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'method': 'm', 'password': 'p', 'plugin': 'v2ray-plugin', 'plugin_opts': 'mode=websocket;tls;host=x=y;;=z;tls;mode=quic; sp =1'}),
      n('ss plugin int opts', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'method': 'm', 'plugin': 'x', 'plugin_opts': 5}),
      n('ss plugin no pw', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'plugin': 'x', 'plugin_opts': ''}),
      n('ss plugin non-string', {'type': 'shadowsocks', 'server': 'a', 'server_port': 1, 'plugin': 5}),
      n('vmess bare', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u'}),
      n('vmess ws', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'alter_id': 2, 'security': 'aes-128-gcm', 'tls': {'enabled': true, 'server_name': 's', 'insecure': true}, 'transport': {'type': 'ws', 'path': '/p', 'headers': {'Host': 'h'}}}),
      n('vmess ws nopath', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'tls': {'insecure': false}, 'transport': {'type': 'ws'}}),
      n('vmess grpc', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'grpc', 'service_name': 'g'}}),
      n('vmess grpc bare', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'grpc'}}),
      n('vmess h2', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'http', 'host': ['a', 'b'], 'path': '/x'}}),
      n('vmess httpupgrade', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'httpupgrade'}}),
      n('vmess transport list', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'transport': ['ws']}),
      n('vmess tls true', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'tls': true}),
      n('vmess alter null', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'uuid': 'u', 'alter_id': null, 'security': null}),
      n('vmess no uuid', {'type': 'vmess', 'server': 'v', 'server_port': 443}),
      n('vless reality', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'flow': 'xtls-rprx-vision', 'tls': {'enabled': true, 'server_name': 'sni', 'utls': {'enabled': true, 'fingerprint': 'chrome'}, 'reality': {'enabled': true, 'public_key': 'pk'}}}),
      n('vless reality sid', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'tls': {'reality': {'public_key': 'pk', 'short_id': 'ab'}}}),
      n('vless reality empty', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'tls': {'reality': {}}}),
      n('vless ws', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'ws', 'path': '/'}}),
      n('vless quic', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'transport': {'type': 'quic'}}),
      n('vless utls nofp', {'type': 'vless', 'server': 'r', 'server_port': 443, 'uuid': 'u', 'tls': {'utls': {'enabled': true}}}),
      n('trojan', {'type': 'trojan', 'server': 't', 'server_port': 443, 'password': 'p', 'tls': {'enabled': true, 'server_name': 's', 'alpn': ['h2', 'http/1.1']}}),
      n('trojan h2', {'type': 'trojan', 'server': 't', 'server_port': 443, 'password': 'p', 'transport': {'type': 'http'}}),
      n('trojan grpc', {'type': 'trojan', 'server': 't', 'server_port': 443, 'password': 'p', 'transport': {'type': 'grpc', 'service_name': 's'}, 'tls': {'insecure': true}}),
      n('trojan alpn empty', {'type': 'trojan', 'server': 't', 'server_port': 443, 'password': 'p', 'tls': {'alpn': []}}),
      n('anytls', {'type': 'anytls', 'server': 'a', 'server_port': 443, 'password': 'p', 'tls': {'server_name': 's', 'insecure': true, 'utls': {'fingerprint': 'ff'}, 'alpn': ['h2']}, 'transport': {'type': 'quic'}}),
      n('anytls bare', {'type': 'anytls', 'server': 'a', 'server_port': 443}),
      n('hy2', {'type': 'hysteria2', 'server': 'h', 'server_port': 443, 'password': 'p', 'obfs': {'type': 'salamander', 'password': 'op'}, 'tls': {'server_name': 's', 'alpn': ['h3']}, 'up_mbps': 100, 'down_mbps': 200.5}),
      n('hy2 bare', {'type': 'hysteria2', 'server': 'h', 'server_port': 443}),
      n('hy2 insecure', {'type': 'hysteria2', 'server': 'h', 'server_port': 443, 'tls': {'insecure': true}, 'up_mbps': 1e21, 'down_mbps': 0.5}),
      n('tuic', {'type': 'tuic', 'server': 'q', 'server_port': 443, 'uuid': 'u', 'password': 'p', 'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'tls': {'server_name': 's', 'alpn': ['h3'], 'insecure': true}}),
      n('tuic bare', {'type': 'tuic', 'server': 'q', 'server_port': 443}),
      n('socks', {'type': 'socks', 'server': 's', 'server_port': 1080, 'username': 'u', 'password': 'p'}),
      n('socks bare', {'type': 'socks', 'server': 's', 'server_port': 1080}),
      n('http', {'type': 'http', 'server': 'h', 'server_port': 80}),
      n('wg', {'type': 'wireguard', 'server': 'h', 'server_port': 80}),
      n('no server', {'type': 'socks', 'server_port': 1080}),
      n('int server', {'type': 'socks', 'server': 1234, 'server_port': 1080.0}),
      n('double port', {'type': 'socks', 'server': 's', 'server_port': 443.9}),
      n('no port', {'type': 'socks', 'server': 's'}),
      n('string port', {'type': 'socks', 'server': 's', 'server_port': '443'}),
      n('sni int', {'type': 'trojan', 'server': 't', 'server_port': 443, 'tls': {'server_name': 5}}),
      n('alpn mixed', {'type': 'trojan', 'server': 't', 'server_port': 443, 'tls': {'alpn': ['h2', 5]}}),
      n('ws headers mixed', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'transport': {'type': 'ws', 'headers': {'a': 1}}}),
      n('ws headers list', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'transport': {'type': 'ws', 'headers': [1]}}),
      n('hy2 obfs list', {'type': 'hysteria2', 'server': 'h', 'server_port': 443, 'obfs': ['x']}),
      n('vmess transport type int', {'type': 'vmess', 'server': 'v', 'server_port': 443, 'transport': {'type': 5}}),
      n('vless reality not map', {'type': 'vless', 'server': 'r', 'server_port': 443, 'tls': {'reality': true, 'utls': 'chrome'}}),
    ]);
    final proxyFor = [
      for (final o in outbounds)
        {
          'node': o,
          'got': _try(() => clashProxyFor(
                ProxyNode(
                  name: '${o['name']}',
                  outbound: Map<String, Object?>.from(o['outbound'] as Map),
                ),
                'tag:${o['name']}',
              )),
        },
    ];

    // ---------------------------------------------------- unique()
    Map<String, Object?> s(String name) => n(name, {'type': 'socks', 'server': 's', 'server_port': 1});
    Map<String, Object?> h(String name) => n(name, {'type': 'http', 'server': 's', 'server_port': 1});
    final tagLists = [
      [s('a'), s('a'), s('a')],
      [s('proxy'), s('auto'), s('DIRECT'), s('REJECT'), s('direct'), s('block'), s('speedtest'), s('auto~fastest')],
      [s(''), s('  '), s(' node '), s('node')],
      [s('region:HK'), s(' region:HK'), s('region:HK'), s('group:x'), s('ssh:y'), s('sub:z')],
      [h('x'), s('x'), h('x'), s('x')],
      [s('x'), h('x 2'), s('x'), s('x 2')],
      [s('a 2'), s('a'), s('a')],
      [s('\uFEFFa'), s('a'), s('\u00A0b\u00A0'), s('b')],
      [h('only')],
      <Map<String, Object?>>[],
    ];
    final unique = [
      for (final list in tagLists)
        {
          'nodes': list,
          'got': _try(() {
            final r = buildClashConfig(
              nodes: [for (final x in list) ProxyNode.fromJson(x)!],
              settings: const ProxySettings(),
              runtime: const RuntimeOptions(controllerPort: 1, secret: 's'),
            );
            return {
              'names': [
                for (final p in r.config['proxies'] as List)
                  if ((p as Map)['type'] == 'socks5') p['name'],
              ],
              'unsupported': r.unsupported,
            };
          }),
        },
    ];

    // ---------------------------------------------------- ssh
    final chains = <Object?>[
      {'id': 'c', 'name': 'n', 'hops': [{'host': 'a', 'port': 22, 'user': 'me', 'key': true}, {'host': 'b', 'port': 2222, 'user': 'ops', 'key': false, 'host_key': 'ssh-ed25519 AAA'}, {'host': 'c'}]},
      {'id': 'one', 'hops': [{'host': 'x', 'host_key': 'k', 'key': false}]},
      {'id': 'skip', 'hops': [{'host': 5}, {'host': 'y', 'port': 22.7, 'user': 7}]},
      {'id': 'nosecret', 'hops': [{'host': 'a'}, {'host': 'b', 'key': false}]},
    ];
    final secrets = {
      'ssh/c/0': 'KEY0',
      'ssh/c/1': 'PW1',
      'ssh/c/2': '',
      'ssh/one/0': 'PW',
      'ssh/skip/0': 'S0',
      'ssh/skip/1': 'S1',
    };
    final ssh = [
      for (final c in chains)
        {
          'chain': c,
          'got': _try(() => clashSshProxies(SshChain.fromJson(c)!, secrets)),
        },
    ];

    // ---------------------------------------------------- hosts
    final hostEntries = [
      {'match': 'exact', 'pattern': 'a.b', 'address': '1.2.3.4'},
      {'match': 'domain', 'pattern': ' x.y ', 'address': ' ::1 '},
      {'match': 'keyword', 'pattern': 'cdn'},
      {'match': 'regex', 'pattern': r'^x\.', 'address': 'null'},
      {'match': 'wildcard', 'pattern': '*.w', 'address': '', 'network': 'home'},
      {'match': 'nope', 'pattern': 'z'},
      {'match': 'exact', 'pattern': ' '},
      {'match': 'exact', 'pattern': 5, 'address': 6},
    ];
    final hosts = paopaoHosts([
      for (final e in hostEntries) ?HostEntry.fromJson(e),
    ]);

    // ---------------------------------------------------- modules
    final goldenModules = <Object?>[];
    for (final f in Directory('$golden/build').listSync().whereType<File>()) {
      if (!f.path.contains('--module--')) continue;
      final d = jsonDecode(f.readAsStringSync()) as Map;
      goldenModules.addAll((d['input'] as Map)['modules'] as List);
      break;
    }
    final moduleSets = <List<Object?>>[
      goldenModules,
      [
        {'id': 'm', 'url': 'u', 'spec': {'name': '', 'rules': ['DOMAIN,a,REJECT', 'DOMAIN,b,PROXY', 'DOMAIN,b,PROXY', 'MATCH,PROXY', 'GEOIP,CN,PROXY,no-resolve', ''], 'hostnames': ['*.x.com', 'a*b', 'q?', 'plain', 'plain'], 'excluded': ['*.no.x.com', 'n?']}},
      ],
      [
        {'id': 'r', 'url': 'https://x/a/b.sgmodule?x=1#f', 'enabled': true, 'spec': {'rewrites': [{'pattern': 'p', 'action': {'op': 'header', 'ops': [['add', 'a', 'b', null]], 'n': 1.0, 'big': 1e21, 'small': 1.5e-7, 'u': '\u2028"\\/<'}, 'response': true, 'body': true}, {'pattern': 'q', 'action': 'bad'}], 'rejects': [{'pattern': 'old', 'kind': 'dict'}, 'x'], 'hostnames': ['h.com']}},
        {'id': 'off', 'url': 'u', 'enabled': false, 'spec': {'name': 'off', 'hostnames': ['off.com'], 'rules': ['DOMAIN,off,REJECT'], 'scripts': [{'name': 's', 'pattern': 'p', 'url': 'u'}]}},
        {'id': 7, 'url': 'https://x/%E5%8E%BB%E5%B9%BF%E5%91%8A.sgmodule', 'enabled': 'yes', 'spec': {'scripts': [{'name': null, 'pattern': null, 'timeout': 3.9, 'argument': '', 'binary': true, 'body': 1}, 'bad', {'cron': '* * * * *', 'argObject': true, 'argument': 'a'}]}},
        {'url': 'no id'},
        'junk',
        {'id': 'nospec', 'url': ''},
      ],
      [
        {'id': 'cron', 'url': 'https://x/', 'spec': {'scripts': [{'name': 'c', 'cron': '0 9 * * *', 'url': 'u'}]}},
      ],
      [
        {'id': 'rw', 'url': 'u', 'spec': {'rewrites': [{'pattern': 'p', 'action': {'op': 'reject'}}]}},
      ],
    ];
    final modules = <Object?>[];
    for (final set in moduleSets) {
      for (final port in [7999, null]) {
        modules.add({
          'modules': set,
          'returnPort': port,
          'got': _try(() {
            final r = moduleConfig(
              [for (final m in set) ?ScriptModule.fromJson(m)],
              proxyTarget: 'proxy',
              returnPort: port,
              utcOffsetMinutes: 480,
            );
            return {
              'proxies': r.proxies,
              'listener': r.listener,
              'rules': r.rules,
            };
          }),
        });
      }
    }

    // ---------------------------------------------------- module names
    final urls = [
      'https://m.example/ad.sgmodule',
      'https://m.example/a/b/',
      'https://m.example',
      'https://m.example/',
      'https://m.example/a/./b/../c.plugin',
      'https://m.example/a/..',
      'https://m.example/%E5%8E%BB.sgmodule',
      'https://m.example/%zz',
      'https://m.example/a%2Fb',
      'https://m.example/%FF',
      'https://m.example/x?y=/z#/w',
      'https://m.example:abc/x',
      'https://m.example:99999/x',
      'https://[::1]/x',
      'https://[zz]/x',
      'http://user:pw@h:8080/p/q.lpx',
      'u',
      '',
      'a/b',
      './a',
      '../a/b',
      'a/../../b',
      '/abs/x',
      '//host/x',
      'file:///C:/x/y.sgmodule',
      'mailto:x',
      '1http://x/y',
      'a b:c/d',
      ':x/y',
      'ht+tp://x/y',
      'https://x/a b/c d',
      'https://x/去广告.sgmodule',
      'https://x/a\\b',
      'https://x/a;b',
      'HTTPS://X/Y',
      'https:x/y',
      'https://x/a/%2e%2e/b',
      'https://x/a/.%2E',
      '?q',
      '#f',
      'a:',
      'https://x/a%',
      'https://x/a%4',
      'https://x/a+b',
      'https://a@b@c/x',
      'https://a b/x',
      'https://x:/y',
      'https://[::1]:80/x',
      'https://[::1/x',
      'https://x]/y',
      'https://a[b/x',
      'http://:80/x',
      'http://x\\y/z',
      'x\\y',
      'mailto:a\\b',
      'file:',
      'file:x',
      '.',
      '..',
      'a/..',
      'a/.',
      'https://x/.',
      'https://x/a/%2E%2E',
      'https://x/a/%2F..',
      'https://x/a/b/..',
      'https://x/a/b/../',
      'https://x/%41%42',
      'https://x/a%252E',
      'https://user@/x',
      'https://x:8a/y',
      'https://[v1.x]/y',
      'https://[fe80::1%25eth0]/y',
      'https://h%41st/y',
      'https://x/y#',
      'https://x/y?',
      'a:b:c',
      'https://x/%e5%8e%bb',
      'https://x/%C3',
      '//',
      '///a',
      'https://x//',
      'https://x//a',
      'a//b',
      'http://x/a\tb',
      'http://x/ a ',
      ' http://x/a',
      'http://x/a\n',
    ];
    final names = [
      for (final u in urls)
        {
          'url': u,
          'got': _try(() => ScriptModule(id: 'x', url: u).name),
        },
    ];

    File(out).writeAsStringSync(
      const JsonEncoder.withIndent(' ').convert({
        'clashProxyFor': proxyFor,
        'unique': unique,
        'ssh': {'secrets': secrets, 'cases': ssh},
        'hosts': {'entries': hostEntries, 'got': hosts},
        'modules': modules,
        'moduleNames': names,
      }),
    );
  });
}
