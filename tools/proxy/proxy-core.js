/**
 * proxy-core.js — 代理链接解析 / 转换核心（浏览器与 Node 通用）
 *
 * 输入协议: vmess / vless / ss / ssr / trojan / hysteria / hysteria2(hy2) /
 *           tuic / socks5(socks) / http(https)
 * 输入容器: 单条链接、每行一条、整段 base64 订阅
 * 输出:     clash(mihomo) YAML / sing-box JSON / v2rayN 链接 / base64 订阅 / 字段表
 *
 * 设计: 纯函数、无第三方依赖，可直接在浏览器里跑（不上传服务器）。
 */
(function (root) {
  'use strict';

  /* ---------------- base64 工具 ---------------- */

  function b64ToBytes(s) {
    s = String(s).replace(/[\r\n\s]/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin;
    if (typeof atob === 'function') {
      bin = atob(s);
    } else {
      bin = Buffer.from(s, 'base64').toString('binary');
    }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64Decode(s) {
    try {
      var bytes = b64ToBytes(s);
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (e) {
      return '';
    }
  }

  function b64Encode(str) {
    var bytes = new TextEncoder().encode(String(str));
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    if (typeof btoa === 'function') return btoa(bin);
    return Buffer.from(bin, 'binary').toString('base64');
  }

  function b64UrlEncode(str) {
    return b64Encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /** 尝试 base64 解码；结果含 : 或换行或协议前缀才算成功 */
  function maybeB64(str) {
    if (!str || !/^[A-Za-z0-9+/=_\-\s]+$/.test(str)) return null;
    var d = b64Decode(str);
    if (!d) return null;
    if (/[^\x00-\x7F]/.test(d) || /:\/\/|@|:/.test(d) || d.indexOf('\n') >= 0) return d;
    return null;
  }

  /* ---------------- 通用解析工具 ---------------- */

  function splitName(link) {
    var i = link.indexOf('#');
    if (i < 0) return { body: link, name: '' };
    var name = link.slice(i + 1);
    try { name = decodeURIComponent(name); } catch (e) {}
    return { body: link.slice(0, i), name: name };
  }

  function parseQuery(qs) {
    var out = {};
    if (!qs) return out;
    qs.split('&').forEach(function (kv) {
      if (!kv) return;
      var i = kv.indexOf('=');
      var k = i < 0 ? kv : kv.slice(0, i);
      var v = i < 0 ? '' : kv.slice(i + 1);
      try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (e) {}
      out[k.toLowerCase()] = v;
    });
    return out;
  }

  function splitHostPort(hp) {
    hp = String(hp || '').trim().replace(/\/$/, '');
    if (hp.charAt(0) === '[') {
      var m = hp.match(/^\[([^\]]+)\](?::(\d+))?$/);
      if (m) return { server: m[1], port: parseInt(m[2] || '443', 10) };
    }
    var i = hp.lastIndexOf(':');
    if (i < 0) return { server: hp, port: 443 };
    return { server: hp.slice(0, i), port: parseInt(hp.slice(i + 1), 10) || 443 };
  }

  function boolish(v) {
    return v === true || v === 1 || v === '1' || v === 'true' || v === 'yes';
  }

  function networkOf(t) {
    t = String(t || 'tcp').toLowerCase();
    if (t === 'http') return 'h2';
    if (t === 'httpupgrade') return 'httpupgrade';
    return t;
  }

  /* ---------------- 各协议解析 ---------------- */

  function parseVmess(raw) {
    var body = raw.slice(8);
    var txt = b64Decode(body);
    if (!txt) return null;
    var c;
    try { c = JSON.parse(txt); } catch (e) { return null; }

    var net = networkOf(c.net || c.network || 'tcp');
    var p = {
      type: 'vmess',
      name: c.ps || c.remark || '',
      server: c.add || c.address || '',
      port: parseInt(c.port, 10) || 443,
      uuid: c.id || '',
      alterId: parseInt(c.aid !== undefined ? c.aid : c.alterId, 10) || 0,
      cipher: c.scy || c.cipher || 'auto',
      network: net,
      tls: c.tls === 'tls' || c.tls === true || c.tls === 'reality',
      sni: c.sni || '',
      alpn: c.alpn ? String(c.alpn).split(',').filter(Boolean) : [],
      fp: c.fp || '',
      allowInsecure: boolish(c.skip_cert_verify) || boolish(c.allowInsecure),
      host: c.host || '',
      path: c.path || (net === 'grpc' ? '' : '/'),
      headerType: c.type || 'none',
      serviceName: net === 'grpc' ? (c.path || '') : ''
    };
    if (!p.server || !p.uuid) return null;
    if (!p.name) p.name = p.server + ':' + p.port;
    return p;
  }

  function parseVless(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(8);
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    if (at < 0) return null;
    var uuid = head.slice(0, at);
    var hp = splitHostPort(head.slice(at + 1));
    var sec = (q.security || 'none').toLowerCase();
    var net = networkOf(q.type || 'tcp');
    var p = {
      type: 'vless',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server,
      port: hp.port,
      uuid: uuid,
      flow: q.flow || '',
      network: net,
      tls: sec === 'tls' || sec === 'reality' || sec === 'xtls',
      security: sec,
      sni: q.sni || q.peer || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : [],
      fp: q.fp || '',
      allowInsecure: boolish(q.allowinsecure) || boolish(q.insecure),
      host: q.host || '',
      path: q.path || (net === 'grpc' ? '' : '/'),
      headerType: q.headertype || 'none',
      serviceName: net === 'grpc' ? (q.servicename || q.path || '') : '',
      pbk: q.pbk || '',
      sid: q.sid || '',
      spx: q.spx || ''
    };
    if (!p.server || !p.uuid) return null;
    return p;
  }

  function parseSS(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(5);
    var plugin = '', pluginOpts = '', method = '', password = '', server = '', port = 0;

    var qi = body.indexOf('?');
    var query = '';
    if (qi >= 0) { query = body.slice(qi + 1); body = body.slice(0, qi); }

    if (body.indexOf('@') >= 0) {
      // SIP002: ss://base64(method:pass)@host:port  /  ss://method:pass@host:port
      var at = body.lastIndexOf('@');
      var userinfo = body.slice(0, at);
      var hp = splitHostPort(body.slice(at + 1));
      server = hp.server; port = hp.port;
      var dec = maybeB64(userinfo);
      var cred = dec && dec.indexOf(':') >= 0 ? dec : userinfo;
      var ci = cred.indexOf(':');
      if (ci < 0) {
        try { cred = decodeURIComponent(cred); } catch (e) {}
        ci = cred.indexOf(':');
      }
      if (ci < 0) return null;
      method = cred.slice(0, ci);
      password = cred.slice(ci + 1);
      try { password = decodeURIComponent(password); } catch (e) {}
    } else {
      // legacy: ss://base64(method:pass@host:port)
      var d = maybeB64(body);
      if (!d) return null;
      var at2 = d.lastIndexOf('@');
      if (at2 < 0) return null;
      var cred2 = d.slice(0, at2);
      var hp2 = splitHostPort(d.slice(at2 + 1));
      server = hp2.server; port = hp2.port;
      var ci2 = cred2.indexOf(':');
      if (ci2 < 0) return null;
      method = cred2.slice(0, ci2);
      password = cred2.slice(ci2 + 1);
    }

    var q = parseQuery(query);
    if (q.plugin) {
      var parts = q.plugin.split(';');
      plugin = parts.shift();
      pluginOpts = parts.join(';');
    }
    if (!server || !method) return null;
    return {
      type: 'ss',
      name: sn.name || (server + ':' + port),
      server: server, port: port,
      method: method, password: password,
      plugin: plugin, pluginOpts: pluginOpts,
      network: 'tcp'
    };
  }

  function parseSSR(raw) {
    var sn = splitName(raw);
    var d = b64Decode(sn.body.slice(6));
    if (!d) return null;
    var qi = d.indexOf('/?');
    var main = qi < 0 ? d : d.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : d.slice(qi + 2));
    var parts = main.split(':');
    if (parts.length < 6) return null;
    var passwordB64 = parts.slice(5).join(':');
    var p = {
      type: 'ssr',
      name: q.remarks ? b64Decode(q.remarks) : (parts[0] + ':' + parts[1]),
      server: parts[0],
      port: parseInt(parts[1], 10) || 443,
      protocol: parts[2],
      method: parts[3],
      obfs: parts[4],
      password: b64Decode(passwordB64),
      protocolParam: q.protoparam ? b64Decode(q.protoparam) : '',
      obfsParam: q.obfsparam ? b64Decode(q.obfsparam) : '',
      group: q.group ? b64Decode(q.group) : '',
      network: 'tcp'
    };
    if (!p.server) return null;
    return p;
  }

  function parseTrojan(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(9);
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    if (at < 0) return null;
    var password = head.slice(0, at);
    try { password = decodeURIComponent(password); } catch (e) {}
    var hp = splitHostPort(head.slice(at + 1));
    var net = networkOf(q.type || 'tcp');
    return {
      type: 'trojan',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      password: password,
      network: net,
      tls: true,
      sni: q.sni || q.peer || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : [],
      fp: q.fp || '',
      allowInsecure: boolish(q.allowinsecure) || boolish(q.insecure) || boolish(q.skip_cert_verify),
      host: q.host || '',
      path: q.path || '/',
      headerType: q.headertype || 'none',
      serviceName: net === 'grpc' ? (q.servicename || q.path || '') : ''
    };
  }

  function parseHysteria(raw) {
    var sn = splitName(raw);
    var isH2 = /^hysteria2:\/\//i.test(raw) || /^hy2:\/\//i.test(raw);
    var prefix = /^hysteria2:\/\//i.test(raw) ? 12 : (/^hy2:\/\//i.test(raw) ? 6 : 11);
    var body = sn.body.slice(prefix);
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    var auth = '', hpStr = head;
    if (at >= 0) { auth = head.slice(0, at); hpStr = head.slice(at + 1); }
    try { auth = decodeURIComponent(auth); } catch (e) {}
    var hp = splitHostPort(hpStr);
    return {
      type: isH2 ? 'hysteria2' : 'hysteria',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      password: auth,
      tls: true,
      sni: q.sni || q.peer || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : (isH2 ? ['h3'] : []),
      allowInsecure: boolish(q.insecure) || boolish(q.allowinsecure),
      obfs: q.obfs || '',
      obfsPassword: q['obfs-password'] || q.obfspassword || '',
      upMbps: parseInt(q.upmbps || q.up || '0', 10) || 0,
      downMbps: parseInt(q.downmbps || q.down || '0', 10) || 0,
      network: 'udp'
    };
  }

  function parseTuic(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(7);
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    if (at < 0) return null;
    var cred = head.slice(0, at);
    try { cred = decodeURIComponent(cred); } catch (e) {}
    var ci = cred.indexOf(':');
    var uuid = ci < 0 ? cred : cred.slice(0, ci);
    var password = ci < 0 ? '' : cred.slice(ci + 1);
    var hp = splitHostPort(head.slice(at + 1));
    return {
      type: 'tuic',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      uuid: uuid, password: password,
      tls: true,
      sni: q.sni || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : ['h3'],
      allowInsecure: boolish(q.insecure) || boolish(q.allow_insecure),
      congestion: q.congestion_control || q.congestion || 'bbr',
      udpRelayMode: q.udp_relay_mode || 'native',
      network: 'udp'
    };
  }

  function parseSocksHttp(raw) {
    var m = raw.match(/^(socks5|socks4|socks|http|https):\/\/(.+)$/i);
    if (!m) return null;
    var type = m[1].toLowerCase().indexOf('socks') === 0 ? 'socks5' : 'http';
    var sn = splitName(m[2]);
    var body = sn.body;
    var qt = body.indexOf('?');
    var q = parseQuery(qt < 0 ? '' : body.slice(qt + 1));
    if (qt >= 0) body = body.slice(0, qt);
    var at = body.lastIndexOf('@');
    var user = '', pass = '', hpStr = body;
    if (at >= 0) {
      var cred = body.slice(0, at);
      try { cred = decodeURIComponent(cred); } catch (e) {}
      var ci = cred.indexOf(':');
      user = ci < 0 ? cred : cred.slice(0, ci);
      pass = ci < 0 ? '' : cred.slice(ci + 1);
      hpStr = body.slice(at + 1);
    }
    var hp = splitHostPort(hpStr);
    return {
      type: type,
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      username: user, password: pass,
      tls: /^https:/i.test(raw),
      network: 'tcp'
    };
  }


  /* ---------------- 冷门协议 ---------------- */

  function parseJuicity(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(10); // juicity://
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    if (at < 0) return null;
    var cred = head.slice(0, at);
    try { cred = decodeURIComponent(cred); } catch (e) {}
    var ci = cred.indexOf(':');
    var uuid = ci < 0 ? cred : cred.slice(0, ci);
    var password = ci < 0 ? '' : cred.slice(ci + 1);
    var hp = splitHostPort(head.slice(at + 1));
    return {
      type: 'juicity',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      uuid: uuid, password: password,
      tls: true,
      sni: q.sni || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : ['h3'],
      allowInsecure: boolish(q.allow_insecure) || boolish(q.insecure) || boolish(q.allowinsecure),
      pinnedCertchainSha256: q.pinned_certchain_sha256 || '',
      network: 'udp'
    };
  }

  function parseAnyTLS(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(9); // anytls://
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    var password = '', hpStr = head;
    if (at >= 0) {
      password = head.slice(0, at);
      try { password = decodeURIComponent(password); } catch (e) {}
      hpStr = head.slice(at + 1);
    }
    var hp = splitHostPort(hpStr);
    return {
      type: 'anytls',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      password: password,
      tls: true,
      sni: q.sni || q.peer || '',
      alpn: q.alpn ? q.alpn.split(',').filter(Boolean) : [],
      fp: q.fp || '',
      allowInsecure: boolish(q.insecure) || boolish(q.allow_insecure) || boolish(q.allowinsecure),
      idleSessionCheckInterval: q.idle_session_check_interval || '',
      network: 'tcp'
    };
  }

  function parseNaive(raw) {
    var sn = splitName(raw);
    var m = sn.body.match(/^naive\+(https|quic):\/\/(.+)$/i);
    if (!m) return null;
    var body = m[2];
    var qi = body.indexOf('?');
    var head = qi < 0 ? body : body.slice(0, qi);
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    var at = head.lastIndexOf('@');
    var user = '', pass = '', hpStr = head;
    if (at >= 0) {
      var cred = head.slice(0, at);
      try { cred = decodeURIComponent(cred); } catch (e) {}
      var ci = cred.indexOf(':');
      user = ci < 0 ? cred : cred.slice(0, ci);
      pass = ci < 0 ? '' : cred.slice(ci + 1);
      hpStr = head.slice(at + 1);
    }
    var hp = splitHostPort(hpStr);
    return {
      type: 'naive',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      username: user, password: pass,
      tls: true,
      sni: q.sni || '',
      allowInsecure: boolish(q.insecure) || boolish(q.allow_insecure),
      network: m[1].toLowerCase() === 'quic' ? 'quic' : 'tcp'
    };
  }

  function parseBrook(raw) {
    var sn = splitName(raw);
    var body = sn.body.slice(8); // brook://
    var qi = body.indexOf('?');
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    if (qi >= 0) body = body.slice(0, qi);
    body = body.replace(/\/+$/, '');
    // brook://server:port  + ?password=  或 brook://password@server:port
    var at = body.lastIndexOf('@');
    var password = q.password || '';
    var hpStr = body;
    if (at >= 0) {
      password = body.slice(0, at) || password;
      try { password = decodeURIComponent(password); } catch (e) {}
      hpStr = body.slice(at + 1);
    }
    var hp = splitHostPort(hpStr);
    return {
      type: 'brook',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      password: password,
      network: 'tcp'
    };
  }

  function parseSsh(raw) {
    var sn = splitName(raw);
    var m = sn.body.match(/^ssh:\/\/(.+)$/i);
    if (!m) return null;
    var body = m[1];
    var qi = body.indexOf('?');
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    if (qi >= 0) body = body.slice(0, qi);
    var at = body.lastIndexOf('@');
    if (at < 0) return null;
    var cred = body.slice(0, at);
    try { cred = decodeURIComponent(cred); } catch (e) {}
    var ci = cred.indexOf(':');
    var user = ci < 0 ? cred : cred.slice(0, ci);
    var pass = ci < 0 ? '' : cred.slice(ci + 1);
    var hp = splitHostPort(body.slice(at + 1));
    return {
      type: 'ssh',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      username: user, password: pass,
      network: 'tcp'
    };
  }

  function parseMieru(raw) {
    var sn = splitName(raw);
    var m = sn.body.match(/^mierus?:\/\/(.+)$/i);
    if (!m) return null;
    // mierus://username:password@host:port?multiplexing=MULTIPLEXING_OFF
    var body = m[1];
    var qi = body.indexOf('?');
    var q = parseQuery(qi < 0 ? '' : body.slice(qi + 1));
    if (qi >= 0) body = body.slice(0, qi);
    var at = body.lastIndexOf('@');
    if (at < 0) return null;
    var cred = body.slice(0, at);
    try { cred = decodeURIComponent(cred); } catch (e) {}
    var ci = cred.indexOf(':');
    var user = ci < 0 ? cred : cred.slice(0, ci);
    var pass = ci < 0 ? '' : cred.slice(ci + 1);
    var hp = splitHostPort(body.slice(at + 1));
    return {
      type: 'mieru',
      name: sn.name || (hp.server + ':' + hp.port),
      server: hp.server, port: hp.port,
      username: user, password: pass,
      transport: (q.transport || 'TCP').toUpperCase(),
      multiplexing: q.multiplexing || 'MULTIPLEXING_OFF',
      network: 'tcp'
    };
  }

  /** WireGuard .conf 文本 -> proxy（支持一次多段，取第一段） */
  function parseWireguardConf(text) {
    var blocks = String(text).split(/\[\s*Peer\s*\]/i);
    if (!/\[\s*Interface\s*\]/i.test(text)) return null;
    var iface = blocks[0];
    var get = function (src, key) {
      var m = src.match(new RegExp('^\\s*' + key + '\\s*=\\s*(.+)$', 'im'));
      return m ? m[1].trim() : '';
    };
    var priv = get(iface, 'PrivateKey');
    var addr = get(iface, 'Address');
    var dns = get(iface, 'DNS');
    var mtu = get(iface, 'MTU');
    var peer = blocks[1] || '';
    var pub = get(peer, 'PublicKey');
    var psk = get(peer, 'PresharedKey');
    var endpoint = get(peer, 'Endpoint');
    var allowed = get(peer, 'AllowedIPs');
    if (!priv || !pub || !endpoint) return null;
    var hp = splitHostPort(endpoint);
    return {
      type: 'wireguard',
      name: 'WireGuard ' + hp.server,
      server: hp.server, port: hp.port,
      privateKey: priv, publicKey: pub, presharedKey: psk,
      localAddress: addr ? addr.split(',').map(function (x) { return x.trim(); }) : [],
      allowedIPs: allowed ? allowed.split(',').map(function (x) { return x.trim(); }) : ['0.0.0.0/0', '::/0'],
      dns: dns ? dns.split(',').map(function (x) { return x.trim(); }) : [],
      mtu: parseInt(mtu, 10) || 0,
      network: 'udp'
    };
  }

  var PARSERS = [
    ['vmess://', parseVmess],
    ['vless://', parseVless],
    ['ssr://', parseSSR],
    ['ss://', parseSS],
    ['trojan://', parseTrojan],
    ['hysteria2://', parseHysteria],
    ['hy2://', parseHysteria],
    ['hysteria://', parseHysteria],
    ['tuic://', parseTuic],
    ['juicity://', parseJuicity],
    ['anytls://', parseAnyTLS],
    ['naive+https://', parseNaive],
    ['naive+quic://', parseNaive],
    ['brook://', parseBrook],
    ['mierus://', parseMieru],
    ['mieru://', parseMieru],
    ['ssh://', parseSsh]
  ];

  /** 解析单条链接，返回 proxy 对象或 null */
  function parseLink(line) {
    line = String(line || '').trim();
    if (!line) return null;
    var low = line.toLowerCase();
    for (var i = 0; i < PARSERS.length; i++) {
      if (low.indexOf(PARSERS[i][0]) === 0) {
        try { return PARSERS[i][1](line); } catch (e) { return null; }
      }
    }
    if (/^(socks5|socks4|socks|http|https):\/\//i.test(line)) {
      try { return parseSocksHttp(line); } catch (e) { return null; }
    }
    return null;
  }

  /**
   * 解析整段文本（自动展开 base64 订阅、按行拆分）
   * 返回 { proxies: [], failed: [{line, reason}] }
   */
  function parseText(text) {
    text = String(text || '').trim();
    if (!text) return { proxies: [], failed: [] };

    // WireGuard .conf 文本
    if (/\[\s*Interface\s*\]/i.test(text) && /\[\s*Peer\s*\]/i.test(text)) {
      var wg = null;
      try { wg = parseWireguardConf(text); } catch (e) { wg = null; }
      if (wg) return { proxies: [wg], failed: [] };
    }

    // 整段是 base64 订阅
    if (!/:\/\//.test(text)) {
      var d = maybeB64(text);
      if (d && /:\/\//.test(d)) text = d;
    }

    var lines = text.split(/[\r\n]+/);
    var proxies = [], failed = [];
    lines.forEach(function (ln) {
      ln = ln.trim();
      if (!ln || ln.charAt(0) === '#' || ln.charAt(0) === '/') return;
      var p = parseLink(ln);
      if (!p) {
        failed.push({ line: ln.slice(0, 120), reason: '无法识别协议或格式错误' });
        return;
      }
      proxies.push(p);
    });
    return { proxies: proxies, failed: failed };
  }

  /* ---------------- 输出: 链接 ---------------- */

  function qs(params) {
    var out = [];
    Object.keys(params).forEach(function (k) {
      var v = params[k];
      if (v === undefined || v === null || v === '' || v === false) return;
      if (Array.isArray(v)) { if (!v.length) return; v = v.join(','); }
      out.push(k + '=' + encodeURIComponent(v));
    });
    return out.length ? '?' + out.join('&') : '';
  }

  function toVmessLink(p) {
    var obj = {
      v: '2', ps: p.name, add: p.server, port: String(p.port),
      id: p.uuid, aid: String(p.alterId || 0), scy: p.cipher || 'auto',
      net: p.network || 'tcp', type: p.headerType || 'none',
      host: p.host || '', path: p.path || '', tls: p.tls ? 'tls' : '',
      sni: p.sni || '', alpn: (p.alpn || []).join(','), fp: p.fp || ''
    };
    return 'vmess://' + b64Encode(JSON.stringify(obj));
  }

  function toVlessLink(p) {
    var q = {
      encryption: 'none',
      security: p.security || (p.tls ? (p.pbk ? 'reality' : 'tls') : 'none'),
      type: p.network || 'tcp',
      sni: p.sni, fp: p.fp, alpn: (p.alpn || []).join(','),
      host: p.host, path: p.network === 'grpc' ? '' : p.path,
      serviceName: p.serviceName,
      flow: p.flow, pbk: p.pbk, sid: p.sid, spx: p.spx
    };
    if (p.allowInsecure) q.allowInsecure = '1';
    return 'vless://' + encodeURIComponent(p.uuid) + '@' + p.server + ':' + p.port +
      qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toSsLink(p) {
    var cred = b64UrlEncode(p.method + ':' + p.password);
    var q = {};
    if (p.plugin) q.plugin = p.plugin + (p.pluginOpts ? ';' + p.pluginOpts : '');
    return 'ss://' + cred + '@' + p.server + ':' + p.port + qs(q) +
      (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toSsrLink(p) {
    var pw = b64UrlEncode(p.password || '');
    var main = [p.server, p.port, p.protocol || 'origin', p.method, p.obfs || 'plain', pw].join(':');
    var q = [];
    if (p.obfsParam) q.push('obfsparam=' + b64UrlEncode(p.obfsParam));
    if (p.protocolParam) q.push('protoparam=' + b64UrlEncode(p.protocolParam));
    if (p.name) q.push('remarks=' + b64UrlEncode(p.name));
    if (p.group) q.push('group=' + b64UrlEncode(p.group));
    return 'ssr://' + b64UrlEncode(main + (q.length ? '/?' + q.join('&') : ''));
  }

  function toTrojanLink(p) {
    var q = {
      type: p.network || 'tcp',
      sni: p.sni, host: p.host, path: p.network === 'grpc' ? '' : p.path,
      serviceName: p.serviceName, alpn: (p.alpn || []).join(','), fp: p.fp
    };
    if (p.allowInsecure) q.allowInsecure = '1';
    return 'trojan://' + encodeURIComponent(p.password || '') + '@' + p.server + ':' + p.port +
      qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toHysteria2Link(p) {
    var q = {
      sni: p.sni, alpn: (p.alpn || []).join(','),
      obfs: p.obfs, 'obfs-password': p.obfsPassword,
      upmbps: p.upMbps || '', downmbps: p.downMbps || ''
    };
    if (p.allowInsecure) q.insecure = '1';
    return 'hysteria2://' + encodeURIComponent(p.password || '') + '@' + p.server + ':' + p.port +
      qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toTuicLink(p) {
    var q = {
      sni: p.sni, alpn: (p.alpn || []).join(','),
      congestion_control: p.congestion, udp_relay_mode: p.udpRelayMode
    };
    if (p.allowInsecure) q.insecure = '1';
    return 'tuic://' + encodeURIComponent(p.uuid + ':' + (p.password || '')) + '@' +
      p.server + ':' + p.port + qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toSocksHttpLink(p) {
    var scheme = p.type === 'http' ? (p.tls ? 'https' : 'http') : 'socks5';
    var cred = '';
    if (p.username) cred = encodeURIComponent(p.username) + (p.password ? ':' + encodeURIComponent(p.password) : '') + '@';
    return scheme + '://' + cred + p.server + ':' + p.port + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toJuicityLink(p) {
    var q = { sni: p.sni, alpn: (p.alpn || []).join(','), pinned_certchain_sha256: p.pinnedCertchainSha256 };
    if (p.allowInsecure) q.allow_insecure = '1';
    return 'juicity://' + encodeURIComponent((p.uuid || '') + ':' + (p.password || '')) + '@' +
      p.server + ':' + p.port + qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toAnyTlsLink(p) {
    var q = { sni: p.sni, alpn: (p.alpn || []).join(','), fp: p.fp };
    if (p.allowInsecure) q.insecure = '1';
    return 'anytls://' + encodeURIComponent(p.password || '') + '@' + p.server + ':' + p.port +
      qs(q) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toNaiveLink(p) {
    var scheme = p.network === 'quic' ? 'naive+quic' : 'naive+https';
    var cred = (p.username || '') + (p.password ? ':' + p.password : '');
    return scheme + '://' + (cred ? encodeURIComponent(cred) + '@' : '') + p.server + ':' + p.port +
      qs({ sni: p.sni }) + (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toBrookLink(p) {
    return 'brook://' + encodeURIComponent(p.password || '') + '@' + p.server + ':' + p.port +
      (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toSshLink(p) {
    var cred = (p.username || '') + (p.password ? ':' + p.password : '');
    return 'ssh://' + (cred ? encodeURIComponent(cred) + '@' : '') + p.server + ':' + p.port +
      (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toMieruLink(p) {
    return 'mierus://' + encodeURIComponent((p.username || '') + ':' + (p.password || '')) + '@' +
      p.server + ':' + p.port + qs({ transport: p.transport, multiplexing: p.multiplexing }) +
      (p.name ? '#' + encodeURIComponent(p.name) : '');
  }

  function toWireguardConf(p) {
    var L = ['[Interface]'];
    L.push('PrivateKey = ' + (p.privateKey || ''));
    if ((p.localAddress || []).length) L.push('Address = ' + p.localAddress.join(', '));
    if ((p.dns || []).length) L.push('DNS = ' + p.dns.join(', '));
    if (p.mtu) L.push('MTU = ' + p.mtu);
    L.push('');
    L.push('[Peer]');
    L.push('PublicKey = ' + (p.publicKey || ''));
    if (p.presharedKey) L.push('PresharedKey = ' + p.presharedKey);
    L.push('Endpoint = ' + p.server + ':' + p.port);
    L.push('AllowedIPs = ' + ((p.allowedIPs || ['0.0.0.0/0']).join(', ')));
    L.push('PersistentKeepalive = 25');
    return L.join('\n');
  }

  function toLink(p) {
    switch (p.type) {
      case 'vmess': return toVmessLink(p);
      case 'vless': return toVlessLink(p);
      case 'ss': return toSsLink(p);
      case 'ssr': return toSsrLink(p);
      case 'trojan': return toTrojanLink(p);
      case 'hysteria2': case 'hysteria': return toHysteria2Link(p);
      case 'tuic': return toTuicLink(p);
      case 'socks5': case 'http': return toSocksHttpLink(p);
      case 'juicity': return toJuicityLink(p);
      case 'anytls': return toAnyTlsLink(p);
      case 'naive': return toNaiveLink(p);
      case 'brook': return toBrookLink(p);
      case 'ssh': return toSshLink(p);
      case 'mieru': return toMieruLink(p);
      case 'wireguard': return '(WireGuard 无标准 URI，请用「WireGuard .conf」输出格式)';
      default: return '';
    }
  }

  /* ---------------- 输出: Clash (mihomo) YAML ---------------- */

  function yq(v) {
    if (v === undefined || v === null) return '""';
    if (typeof v === 'boolean' || typeof v === 'number') return String(v);
    return JSON.stringify(String(v));
  }

  function clashProxy(p, idx) {
    var name = p.name || (p.type + '-' + idx);
    var L = [];
    var t = p.type;

    if (t === 'vmess') {
      L.push('  - name: ' + yq(name));
      L.push('    type: vmess');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    uuid: ' + yq(p.uuid));
      L.push('    alterId: ' + (p.alterId || 0));
      L.push('    cipher: ' + yq(p.cipher || 'auto'));
      L.push('    udp: true');
      if (p.tls) L.push('    tls: true');
      if (p.sni) L.push('    servername: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      if (p.fp) L.push('    client-fingerprint: ' + yq(p.fp));
      if (p.network === 'ws') {
        L.push('    network: ws');
        L.push('    ws-opts:');
        if (p.path) L.push('      path: ' + yq(p.path));
        if (p.host) { L.push('      headers:'); L.push('        Host: ' + yq(p.host)); }
      } else if (p.network === 'grpc') {
        L.push('    network: grpc');
        L.push('    grpc-opts:');
        L.push('      grpc-service-name: ' + yq(p.serviceName || ''));
      } else if (p.network === 'h2') {
        L.push('    network: h2');
        L.push('    h2-opts:');
        if (p.path) L.push('      path: ' + yq(p.path));
        if (p.host) L.push('      host: [' + yq(p.host) + ']');
      } else {
        L.push('    network: tcp');
      }
      return L.join('\n');
    }

    if (t === 'vless') {
      L.push('  - name: ' + yq(name));
      L.push('    type: vless');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    uuid: ' + yq(p.uuid));
      L.push('    udp: true');
      if (p.flow) L.push('    flow: ' + yq(p.flow));
      var sec = p.security || (p.tls ? 'tls' : 'none');
      if (sec !== 'none') {
        L.push('    tls: true');
        if (p.sni) L.push('    servername: ' + yq(p.sni));
        if (p.allowInsecure) L.push('    skip-cert-verify: true');
        if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
        if (p.fp) L.push('    client-fingerprint: ' + yq(p.fp));
        if (sec === 'reality') {
          L.push('    reality-opts:');
          L.push('      public-key: ' + yq(p.pbk || ''));
          if (p.sid) L.push('      short-id: ' + yq(p.sid));
        }
      }
      if (p.network === 'ws') {
        L.push('    network: ws');
        L.push('    ws-opts:');
        if (p.path) L.push('      path: ' + yq(p.path));
        if (p.host) { L.push('      headers:'); L.push('        Host: ' + yq(p.host)); }
      } else if (p.network === 'grpc') {
        L.push('    network: grpc');
        L.push('    grpc-opts:');
        L.push('      grpc-service-name: ' + yq(p.serviceName || ''));
      } else {
        L.push('    network: tcp');
      }
      return L.join('\n');
    }

    if (t === 'ss') {
      L.push('  - name: ' + yq(name));
      L.push('    type: ss');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    cipher: ' + yq(p.method));
      L.push('    password: ' + yq(p.password));
      L.push('    udp: true');
      if (p.plugin) {
        L.push('    plugin: ' + yq(p.plugin));
        if (p.pluginOpts) {
          L.push('    plugin-opts:');
          p.pluginOpts.split(';').forEach(function (kv) {
            var i = kv.indexOf('=');
            if (i < 0) { L.push('      ' + kv + ': true'); return; }
            L.push('      ' + kv.slice(0, i) + ': ' + yq(kv.slice(i + 1)));
          });
        }
      }
      return L.join('\n');
    }

    if (t === 'ssr') {
      L.push('  - name: ' + yq(name));
      L.push('    type: ssr');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    cipher: ' + yq(p.method));
      L.push('    password: ' + yq(p.password));
      L.push('    protocol: ' + yq(p.protocol || 'origin'));
      L.push('    obfs: ' + yq(p.obfs || 'plain'));
      if (p.protocolParam) L.push('    protocol-param: ' + yq(p.protocolParam));
      if (p.obfsParam) L.push('    obfs-param: ' + yq(p.obfsParam));
      L.push('    udp: true');
      return L.join('\n');
    }

    if (t === 'trojan') {
      L.push('  - name: ' + yq(name));
      L.push('    type: trojan');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    password: ' + yq(p.password));
      L.push('    udp: true');
      if (p.sni) L.push('    sni: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      if (p.fp) L.push('    client-fingerprint: ' + yq(p.fp));
      if (p.network === 'ws') {
        L.push('    network: ws');
        L.push('    ws-opts:');
        if (p.path) L.push('      path: ' + yq(p.path));
        if (p.host) { L.push('      headers:'); L.push('        Host: ' + yq(p.host)); }
      } else if (p.network === 'grpc') {
        L.push('    network: grpc');
        L.push('    grpc-opts:');
        L.push('      grpc-service-name: ' + yq(p.serviceName || ''));
      }
      return L.join('\n');
    }

    if (t === 'hysteria2' || t === 'hysteria') {
      L.push('  - name: ' + yq(name));
      L.push('    type: hysteria2');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    password: ' + yq(p.password || ''));
      if (p.sni) L.push('    sni: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      if (p.upMbps) L.push('    up: ' + yq(p.upMbps + ' Mbps'));
      if (p.downMbps) L.push('    down: ' + yq(p.downMbps + ' Mbps'));
      if (p.obfs) {
        L.push('    obfs: ' + yq(p.obfs));
        if (p.obfsPassword) L.push('    obfs-password: ' + yq(p.obfsPassword));
      }
      return L.join('\n');
    }

    if (t === 'tuic') {
      L.push('  - name: ' + yq(name));
      L.push('    type: tuic');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    uuid: ' + yq(p.uuid));
      L.push('    password: ' + yq(p.password || ''));
      if (p.sni) L.push('    sni: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      if (p.congestion) L.push('    congestion-controller: ' + yq(p.congestion));
      if (p.udpRelayMode) L.push('    udp-relay-mode: ' + yq(p.udpRelayMode));
      return L.join('\n');
    }

    if (t === 'wireguard') {
      L.push('  - name: ' + yq(name));
      L.push('    type: wireguard');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      if ((p.localAddress || []).length) L.push('    ip: ' + yq(p.localAddress[0].split('/')[0]));
      L.push('    private-key: ' + yq(p.privateKey || ''));
      L.push('    public-key: ' + yq(p.publicKey || ''));
      if (p.presharedKey) L.push('    preshared-key: ' + yq(p.presharedKey));
      if ((p.dns || []).length) L.push('    dns: [' + p.dns.map(yq).join(', ') + ']');
      if (p.mtu) L.push('    mtu: ' + p.mtu);
      L.push('    udp: true');
      return L.join('\n');
    }

    if (t === 'anytls') {
      L.push('  - name: ' + yq(name));
      L.push('    type: anytls');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    password: ' + yq(p.password || ''));
      if (p.sni) L.push('    sni: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if (p.fp) L.push('    client-fingerprint: ' + yq(p.fp));
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      L.push('    udp: true');
      return L.join('\n');
    }

    if (t === 'juicity') {
      L.push('  - name: ' + yq(name));
      L.push('    type: juicity');
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      L.push('    uuid: ' + yq(p.uuid || ''));
      L.push('    password: ' + yq(p.password || ''));
      if (p.sni) L.push('    sni: ' + yq(p.sni));
      if (p.allowInsecure) L.push('    skip-cert-verify: true');
      if ((p.alpn || []).length) L.push('    alpn: [' + p.alpn.map(yq).join(', ') + ']');
      return L.join('\n');
    }

    if (t === 'socks5' || t === 'http') {
      L.push('  - name: ' + yq(name));
      L.push('    type: ' + t);
      L.push('    server: ' + yq(p.server));
      L.push('    port: ' + p.port);
      if (p.username) L.push('    username: ' + yq(p.username));
      if (p.password) L.push('    password: ' + yq(p.password));
      if (t === 'http' && p.tls) L.push('    tls: true');
      L.push('    udp: true');
      return L.join('\n');
    }

    return '';
  }

  function toClash(proxies) {
    var names = proxies.map(function (p, i) { return p.name || (p.type + '-' + (i + 1)); });
    var out = [];
    out.push('# 由 代理链接转换工具 生成 · ' + new Date().toISOString().slice(0, 19).replace('T', ' '));
    out.push('mixed-port: 7890');
    out.push('allow-lan: false');
    out.push('mode: rule');
    out.push('log-level: info');
    out.push('');
    out.push('proxies:');
    proxies.forEach(function (p, i) { out.push(clashProxy(p, i + 1)); });
    out.push('');
    out.push('proxy-groups:');
    out.push('  - name: 节点选择');
    out.push('    type: select');
    out.push('    proxies:');
    out.push('      - 自动选择');
    names.forEach(function (n) { out.push('      - ' + yq(n)); });
    out.push('      - DIRECT');
    out.push('  - name: 自动选择');
    out.push('    type: url-test');
    out.push('    url: http://www.gstatic.com/generate_204');
    out.push('    interval: 300');
    out.push('    tolerance: 50');
    out.push('    proxies:');
    names.forEach(function (n) { out.push('      - ' + yq(n)); });
    out.push('');
    out.push('rules:');
    out.push('  - GEOIP,LAN,DIRECT,no-resolve');
    out.push('  - GEOIP,CN,DIRECT');
    out.push('  - MATCH,节点选择');
    return out.join('\n');
  }

  /* ---------------- 输出: sing-box JSON ---------------- */

  function singboxProxy(p, idx) {
    var t = p.type;
    var o = { tag: p.name || (t + '-' + idx), type: t, server: p.server, server_port: p.port };

    if (t === 'vmess') {
      o.uuid = p.uuid; o.security = p.cipher || 'auto'; o.alter_id = p.alterId || 0;
    } else if (t === 'vless') {
      o.uuid = p.uuid;
      if (p.flow) o.flow = p.flow;
    } else if (t === 'ss') {
      o.method = p.method; o.password = p.password;
      if (p.plugin === 'obfs-local' || p.plugin === 'simple-obfs') {
        var obfs = {}, opt = p.pluginOpts || '';
        opt.split(';').forEach(function (kv) {
          var i = kv.indexOf('=');
          if (i > 0) obfs[kv.slice(0, i)] = kv.slice(i + 1);
        });
        o.plugin = 'obfs-local';
        o.plugin_opts = (obfs.obfs ? 'obfs=' + obfs.obfs : '') + (obfs['obfs-host'] ? ';obfs-host=' + obfs['obfs-host'] : '');
      } else if (p.plugin) {
        o.plugin = p.plugin;
        o.plugin_opts = p.pluginOpts || '';
      }
    } else if (t === 'ssr') {
      o.method = p.method; o.password = p.password;
      o.protocol = p.protocol || 'origin'; o.obfs = p.obfs || 'plain';
      if (p.protocolParam) o.protocol_param = p.protocolParam;
      if (p.obfsParam) o.obfs_param = p.obfsParam;
    } else if (t === 'trojan') {
      o.password = p.password;
    } else if (t === 'hysteria2') {
      if (t === 'hysteria') o.type = 'hysteria';
      o.password = p.password || '';
      if (p.upMbps) o.up_mbps = p.upMbps;
      if (p.downMbps) o.down_mbps = p.downMbps;
      if (p.obfs) { o.obfs = { type: p.obfs, password: p.obfsPassword || '' }; }
    } else if (t === 'tuic') {
      o.uuid = p.uuid; o.password = p.password || '';
      if (p.congestion) o.congestion_control = p.congestion;
      if (p.udpRelayMode) o.udp_relay_mode = p.udpRelayMode;
    } else if (t === 'socks5' || t === 'http') {
      if (p.username) o.username = p.username;
      if (p.password) o.password = p.password;
    }

    if (t === 'wireguard') {
      o.local_address = p.localAddress || ['10.0.0.2/32'];
      o.private_key = p.privateKey || '';
      o.peer_public_key = p.publicKey || '';
      if (p.presharedKey) o.pre_shared_key = p.presharedKey;
      if (p.mtu) o.mtu = p.mtu;
      return o;
    }
    if (t === 'anytls') o.password = p.password || '';
    if (t === 'naive') { o.username = p.username || ''; o.password = p.password || ''; }
    if (t === 'ssh') { o.user = p.username || ''; o.password = p.password || ''; }
    if (t === 'mieru') {
      o.username = p.username || ''; o.password = p.password || '';
      o.transport = p.transport || 'TCP';
      o.multiplexing = p.multiplexing || 'MULTIPLEXING_OFF';
    }
    if (t === 'juicity' || t === 'brook') {
      o.uuid = p.uuid || ''; o.password = p.password || '';
    }

    // TLS
    var sec = p.security || '';
    if (p.tls || sec === 'tls' || sec === 'reality') {
      var tls = { enabled: true };
      if (p.sni) tls.server_name = p.sni;
      if (p.allowInsecure) tls.insecure = true;
      if ((p.alpn || []).length) tls.alpn = p.alpn;
      if (p.fp) tls.utls = { enabled: true, fingerprint: p.fp };
      if (sec === 'reality') {
        tls.reality = { enabled: true, public_key: p.pbk || '', short_id: p.sid || '' };
      }
      o.tls = tls;
    }

    // 传输
    if (p.network === 'ws') {
      var tr = { type: 'ws', path: p.path || '/', max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' };
      if (p.host) tr.headers = { Host: p.host };
      o.transport = tr;
    } else if (p.network === 'grpc') {
      o.transport = { type: 'grpc', service_name: p.serviceName || '' };
    } else if (p.network === 'h2') {
      var h2 = { type: 'http' };
      if (p.host) h2.host = [p.host];
      if (p.path) h2.path = p.path;
      o.transport = h2;
    }
    return o;
  }

  function toSingbox(proxies) {
    var obj = {
      log: { level: 'info', timestamp: true },
      dns: {
        servers: [
          { tag: 'google', address: 'tls://8.8.8.8' },
          { tag: 'local', address: '223.5.5.5', detour: 'direct' }
        ],
        rules: [{ geosite: ['cn'], server: 'local' }],
        final: 'google'
      },
      inbounds: [
        { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 },
        { type: 'tun', tag: 'tun-in', inet4_address: '172.19.0.1/30', auto_route: true, strict_route: true, stack: 'mixed' }
      ],
      outbounds: proxies.map(function (p, i) { return singboxProxy(p, i + 1); }),
      route: { rules: [{ geoip: ['cn'], outbound: 'direct' }], final: proxies.length ? (proxies[0].name || 'vmess-1') : 'direct' }
    };
    obj.outbounds.push({ type: 'direct', tag: 'direct' });
    obj.outbounds.push({ type: 'block', tag: 'block' });
    return JSON.stringify(obj, null, 2);
  }


  /* ---------------- 输出: 路由器 / 其他客户端 ---------------- */

  // 各目标格式支持哪些协议
  var SUPPORT = {
    clash: ['vmess', 'vless', 'ss', 'ssr', 'trojan', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'anytls', 'juicity', 'socks5', 'http'],
    singbox: ['vmess', 'vless', 'ss', 'ssr', 'trojan', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'anytls', 'naive', 'ssh', 'mieru', 'socks5', 'http'],
    surge: ['ss', 'vmess', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'],
    quanx: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'],
    loon: ['ss', 'vmess', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'],
    passwall: ['ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'],
    openclash: ['vmess', 'vless', 'ss', 'ssr', 'trojan', 'hysteria2', 'tuic', 'socks5', 'http'],
    wireguard: ['wireguard']
  };

  function filterFor(proxies, target) {
    var allow = SUPPORT[target] || [];
    var ok = [], skipped = [];
    proxies.forEach(function (p) {
      if (allow.indexOf(p.type) >= 0) ok.push(p);
      else skipped.push(p);
    });
    return { ok: ok, skipped: skipped };
  }

  function skippedNote(skipped, target) {
    if (!skipped.length) return '';
    var types = {};
    skipped.forEach(function (p) { types[p.type] = (types[p.type] || 0) + 1; });
    var txt = Object.keys(types).map(function (k) { return k + '×' + types[k]; }).join(', ');
    return '# 注意: 以下协议 ' + target + ' 不支持，已跳过 -> ' + txt + '\n';
  }

  function surgeLine(p, idx) {
    var n = p.name || (p.type + '-' + idx), L = [];
    if (p.type === 'ss') {
      L.push(n + ' = ss, ' + p.server + ', ' + p.port + ', encrypt-method=' + p.method +
        ', password=' + p.password + ', udp-relay=true');
    } else if (p.type === 'vmess') {
      var parts = [n + ' = vmess, ' + p.server + ', ' + p.port,
        'username=' + p.uuid, 'udp-relay=true'];
      if (p.tls) parts.push('tls=true');
      if (p.sni) parts.push('sni=' + p.sni);
      if (p.allowInsecure) parts.push('skip-cert-verify=true');
      if (p.network === 'ws') {
        parts.push('ws=true', 'ws-path=' + (p.path || '/'));
        if (p.host) parts.push('ws-headers=Host:' + p.host);
      }
      L.push(parts.join(', '));
    } else if (p.type === 'trojan') {
      var t = [n + ' = trojan, ' + p.server + ', ' + p.port, 'password=' + p.password];
      if (p.sni) t.push('sni=' + p.sni);
      if (p.allowInsecure) t.push('skip-cert-verify=true');
      if (p.network === 'ws') {
        t.push('ws=true', 'ws-path=' + (p.path || '/'));
        if (p.host) t.push('ws-headers=Host:' + p.host);
      }
      L.push(t.join(', '));
    } else if (p.type === 'hysteria2') {
      var h = [n + ' = hysteria2, ' + p.server + ', ' + p.port, 'password=' + (p.password || '')];
      if (p.sni) h.push('sni=' + p.sni);
      if (p.allowInsecure) h.push('skip-cert-verify=true');
      L.push(h.join(', '));
    } else if (p.type === 'tuic') {
      var u = [n + ' = tuic, ' + p.server + ', ' + p.port, 'uuid=' + p.uuid, 'password=' + (p.password || '')];
      if (p.sni) u.push('sni=' + p.sni);
      if (p.allowInsecure) u.push('skip-cert-verify=true');
      L.push(u.join(', '));
    } else if (p.type === 'socks5' || p.type === 'http') {
      var sc = [n + ' = ' + p.type, p.server + ', ' + p.port];
      if (p.username) sc.push('username=' + p.username);
      if (p.password) sc.push('password=' + p.password);
      L.push(sc.join(', '));
    }
    return L.join('');
  }

  function toSurge(proxies) {
    var f = filterFor(proxies, 'surge');
    var out = [];
    out.push('#!MANAGED-CONFIG 由代理链接转换工具生成');
    out.push('');
    out.push('[General]');
    out.push('loglevel = notify');
    out.push('dns-server = 223.5.5.5, 8.8.8.8');
    out.push('');
    out.push('[Proxy]');
    f.ok.forEach(function (p, i) { var l = surgeLine(p, i + 1); if (l) out.push(l); });
    out.push('DIRECT = direct');
    out.push('');
    out.push('[Proxy Group]');
    out.push('Proxy = select, ' + f.ok.map(function (p, i) { return p.name || (p.type + '-' + (i + 1)); }).join(', ') + ', DIRECT');
    out.push('');
    out.push('[Rule]');
    out.push('GEOIP,CN,DIRECT');
    out.push('FINAL,Proxy');
    return skippedNote(f.skipped, 'Surge') + out.join('\n');
  }

  function quanxLine(p, idx) {
    var n = p.name || (p.type + '-' + idx);
    if (p.type === 'ss') {
      return 'shadowsocks=' + p.server + ':' + p.port + ', method=' + p.method +
        ', password=' + p.password + ', fast-open=false, udp-relay=true, tag=' + n;
    }
    if (p.type === 'vmess') {
      var q = ['vmess=' + p.server + ':' + p.port, 'method=chacha20-poly1305',
        'password=' + p.uuid, 'fast-open=false', 'udp-relay=true'];
      if (p.network === 'ws') {
        q.push('obfs=ws');
        if (p.host) q.push('obfs-host=' + p.host);
        q.push('obfs-uri=' + (p.path || '/'));
      } else if (p.network === 'h2') {
        q.push('obfs=over-tls', 'obfs-host=' + (p.sni || p.server));
      }
      if (p.tls) { q.push('tls-verification=' + (p.allowInsecure ? 'false' : 'true')); }
      if (p.sni) q.push('obfs-host=' + p.sni);
      q.push('tag=' + n);
      return q.join(', ');
    }
    if (p.type === 'trojan') {
      var t = ['trojan=' + p.server + ':' + p.port, 'password=' + p.password, 'over-tls=true'];
      if (p.sni) t.push('tls-host=' + p.sni);
      if (p.allowInsecure) t.push('tls-verification=false');
      if (p.network === 'ws') { t.push('obfs=wss'); t.push('obfs-uri=' + (p.path || '/')); }
      t.push('tag=' + n);
      return t.join(', ');
    }
    if (p.type === 'hysteria2') {
      return 'hysteria2=' + p.server + ':' + p.port + ', password=' + (p.password || '') +
        (p.sni ? ', tls-host=' + p.sni : '') + ' tag=' + n;
    }
    if (p.type === 'tuic') {
      return 'tuic=' + p.server + ':' + p.port + ', token=' + (p.password || '') +
        (p.sni ? ', tls-host=' + p.sni : '') + ' tag=' + n;
    }
    if (p.type === 'socks5' || p.type === 'http') {
      return p.type + '=' + p.server + ':' + p.port +
        (p.username ? ', username=' + p.username : '') +
        (p.password ? ', password=' + p.password : '') + ', tag=' + n;
    }
    return '';
  }

  function toQuantumultX(proxies) {
    var f = filterFor(proxies, 'quanx');
    var out = ['[general]', 'network_check_url=http://www.gstatic.com/generate_204', ''];
    out.push('[server_local]');
    f.ok.forEach(function (p, i) { var l = quanxLine(p, i + 1); if (l) out.push(l); });
    out.push('');
    out.push('[policy]');
    out.push('static=Proxy, ' + f.ok.map(function (p, i) { return p.name || (p.type + '-' + (i + 1)); }).join(', ') + ', direct');
    out.push('');
    out.push('[filter_local]');
    out.push('geoip, cn, direct');
    out.push('final, Proxy');
    return skippedNote(f.skipped, 'Quantumult X') + out.join('\n');
  }

  function loonLine(p, idx) {
    var n = p.name || (p.type + '-' + idx);
    if (p.type === 'ss') {
      return n + ' = Shadowsocks,' + p.server + ',' + p.port + ',' + p.method + ',"' + p.password + '"';
    }
    if (p.type === 'vmess') {
      return n + ' = vmess,' + p.server + ',' + p.port + ',"chacha20-ietf-poly1305","' + p.uuid + '"';
    }
    if (p.type === 'trojan') {
      return n + ' = trojan,' + p.server + ',' + p.port + ',"' + p.password + '"';
    }
    if (p.type === 'hysteria2') {
      return n + ' = hysteria2,' + p.server + ',' + p.port + ',"' + (p.password || '') + '"';
    }
    if (p.type === 'tuic') {
      return n + ' = tuic,' + p.server + ',' + p.port + ',"' + p.uuid + '","' + (p.password || '') + '"';
    }
    if (p.type === 'socks5' || p.type === 'http') {
      return n + ' = ' + p.type + ',' + p.server + ',' + p.port + ',"' + (p.username || '') + '","' + (p.password || '') + '"';
    }
    return '';
  }

  function toLoon(proxies) {
    var f = filterFor(proxies, 'loon');
    var out = ['[General]', 'ipv6=true', ''];
    out.push('[Proxy]');
    f.ok.forEach(function (p, i) { var l = loonLine(p, i + 1); if (l) out.push(l); });
    out.push('DIRECT = direct');
    out.push('');
    out.push('[Proxy Group]');
    out.push('Proxy = select,' + f.ok.map(function (p, i) { return p.name || (p.type + '-' + (i + 1)); }).join(', ') + ',DIRECT');
    out.push('');
    out.push('[Rule]');
    out.push('GEOIP,CN,DIRECT');
    out.push('FINAL,Proxy');
    return skippedNote(f.skipped, 'Loon') + out.join('\n');
  }

  /** 路由器插件（OpenWrt PassWall / SSR Plus+ / Merlin / Koolshare）批量导入链接 */
  function toPassWall(proxies, opts) {
    opts = opts || {};
    var f = filterFor(proxies, 'passwall');
    var out = [];
    out.push('# OpenWrt PassWall / SSR Plus+ / ssrplus 批量导入链接');
    out.push('# 用法: 路由器后台 -> 节点列表 -> 批量添加/导入 -> 粘贴以下每行');
    out.push('# 注: Koolshare / Merlin 的 SS 插件只认 ss:// 链接，其余协议请用 PassWall');
    if (skippedNote(f.skipped, 'PassWall')) out.push(skippedNote(f.skipped, 'PassWall').trim());
    out.push('');
    f.ok.forEach(function (p) {
      if (opts.ssOnly && p.type !== 'ss') return;
      var l = toLink(p);
      if (l) out.push(l);
    });
    return out.join('\n');
  }

  /** OpenClash / Mihomo 路由器配置（带 dns 与 redir-host） */
  function toOpenClash(proxies) {
    var f = filterFor(proxies, 'openclash');
    var names = f.ok.map(function (p, i) { return p.name || (p.type + '-' + (i + 1)); });
    var out = [];
    out.push('# OpenClash / Mihomo 通用配置（路由器）');
    out.push('mixed-port: 7890');
    out.push('redir-port: 7892');
    out.push('tproxy-port: 7895');
    out.push('allow-lan: true');
    out.push('bind-address: "*"');
    out.push('mode: rule');
    out.push('log-level: info');
    out.push('external-controller: 0.0.0.0:9090');
    out.push('ipv6: true');
    out.push('');
    out.push('dns:');
    out.push('  enable: true');
    out.push('  ipv6: true');
    out.push('  enhanced-mode: fake-ip');
    out.push('  fake-ip-range: 198.18.0.1/16');
    out.push('  nameserver:');
    out.push('    - 223.5.5.5');
    out.push('    - 119.29.29.29');
    out.push('  fallback:');
    out.push('    - https://1.1.1.1/dns-query');
    out.push('    - tls://8.8.8.8:853');
    out.push('');
    out.push('proxies:');
    f.ok.forEach(function (p, i) { out.push(clashProxy(p, i + 1)); });
    out.push('');
    out.push('proxy-groups:');
    out.push('  - name: 节点选择');
    out.push('    type: select');
    out.push('    proxies:');
    out.push('      - 自动选择');
    names.forEach(function (n) { out.push('      - ' + yq(n)); });
    out.push('      - DIRECT');
    out.push('  - name: 自动选择');
    out.push('    type: url-test');
    out.push('    url: http://www.gstatic.com/generate_204');
    out.push('    interval: 300');
    out.push('    proxies:');
    names.forEach(function (n) { out.push('      - ' + yq(n)); });
    out.push('');
    out.push('rules:');
    out.push('  - GEOIP,LAN,DIRECT,no-resolve');
    out.push('  - GEOIP,CN,DIRECT');
    out.push('  - MATCH,节点选择');
    return skippedNote(f.skipped, 'OpenClash') + out.join('\n');
  }

  function toWireguardBundle(proxies) {
    var wgs = proxies.filter(function (p) { return p.type === 'wireguard'; });
    if (!wgs.length) return '# 没有可导出的 WireGuard 节点（需要粘贴 [Interface]/[Peer] 格式的 .conf 内容）\n';
    return wgs.map(function (p) { return toWireguardConf(p); }).join('\n\n');
  }

  /* ---------------- 输出: v2rayN 链接清单 ---------------- */

  function toLinkList(proxies) {
    return proxies.map(toLink).filter(Boolean).join('\n');
  }

  function toBase64Sub(proxies) {
    var txt = toLinkList(proxies);
    return b64Encode(txt);
  }

  /** 字段表（用于页面展示解析细节） */
  function describe(p) {
    var rows = [
      ['协议', p.type],
      ['名称', p.name || ''],
      ['服务器', p.server],
      ['端口', String(p.port)]
    ];
    if (p.uuid) rows.push(['UUID', p.uuid]);
    if (p.password) rows.push(['密码', p.password]);
    if (p.method) rows.push(['加密', p.method]);
    if (p.cipher) rows.push(['加密', p.cipher]);
    if (p.alterId !== undefined && p.type === 'vmess') rows.push(['alterId', String(p.alterId)]);
    if (p.flow) rows.push(['flow', p.flow]);
    if (p.network) rows.push(['传输', p.network]);
    if (p.path) rows.push(['path', p.path]);
    if (p.host) rows.push(['host', p.host]);
    if (p.serviceName) rows.push(['serviceName', p.serviceName]);
    if (p.tls) rows.push(['TLS', 'yes']);
    if (p.sni) rows.push(['SNI', p.sni]);
    if (p.fp) rows.push(['指纹', p.fp]);
    if ((p.alpn || []).length) rows.push(['ALPN', p.alpn.join(',')]);
    if (p.pbk) rows.push(['reality pbk', p.pbk]);
    if (p.sid) rows.push(['reality sid', p.sid]);
    if (p.plugin) rows.push(['插件', p.plugin + (p.pluginOpts ? ';' + p.pluginOpts : '')]);
    if (p.obfs) rows.push(['混淆', p.obfs]);
    if (p.congestion) rows.push(['拥塞控制', p.congestion]);
    if (p.upMbps) rows.push(['上行', p.upMbps + ' Mbps']);
    if (p.downMbps) rows.push(['下行', p.downMbps + ' Mbps']);
    return rows;
  }

  var api = {
    parseLink: parseLink,
    parseText: parseText,
    toLink: toLink,
    toLinkList: toLinkList,
    toClash: toClash,
    toSingbox: toSingbox,
    toBase64Sub: toBase64Sub,
    toSurge: toSurge,
    toQuantumultX: toQuantumultX,
    toLoon: toLoon,
    toPassWall: toPassWall,
    toOpenClash: toOpenClash,
    toWireguardBundle: toWireguardBundle,
    filterFor: filterFor,
    describe: describe,
    b64Encode: b64Encode,
    b64Decode: b64Decode
  };

  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ProxyCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
