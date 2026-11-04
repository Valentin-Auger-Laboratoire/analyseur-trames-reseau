// =====================================================================
//  Analyseur de trames réseau : moteur (sans interface).
//  - lecture des fichiers pcap (libpcap, µs ou ns, les deux boutismes)
//    et pcapng (blocs SHB, IDB, EPB, SPB) ;
//  - décodage : Ethernet, 802.1Q, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS,
//    HTTP, TLS (ClientHello : SNI), FTP, Telnet ;
//  - vérification des sommes de contrôle IPv4, ICMP, TCP et UDP ;
//  - analyse : conversations, poignée de main TCP, retransmissions,
//    réinitialisations, scans de ports, identifiants en clair.
//  Chaque champ décodé garde sa position (offset, longueur) dans la
//  trame, pour surligner les octets dans la vue hexadécimale.
// =====================================================================
(function (root) {
  'use strict';

  // ------------------------------------------------------------------
  //  Lecture des fichiers de capture
  // ------------------------------------------------------------------
  const LINK = { 1: 'Ethernet', 101: 'IP brut', 228: 'IPv4 brut', 229: 'IPv6 brut', 113: 'Linux cooked' };

  function readPcap(buf) {
    const dv = new DataView(buf);
    if (buf.byteLength < 24) throw new Error('fichier trop court');
    const magic = dv.getUint32(0, false);
    if (magic === 0x0a0d0d0a) return readPcapng(buf);
    let le, nano;
    if (magic === 0xa1b2c3d4) { le = false; nano = false; }
    else if (magic === 0xd4c3b2a1) { le = true; nano = false; }
    else if (magic === 0xa1b23c4d) { le = false; nano = true; }
    else if (magic === 0x4d3cb2a1) { le = true; nano = true; }
    else throw new Error('format inconnu (ni pcap ni pcapng)');
    const linktype = dv.getUint32(20, le) & 0x0fffffff;
    const packets = [];
    let off = 24;
    while (off + 16 <= buf.byteLength) {
      const sec = dv.getUint32(off, le), frac = dv.getUint32(off + 4, le);
      const incl = dv.getUint32(off + 8, le), orig = dv.getUint32(off + 12, le);
      off += 16;
      if (off + incl > buf.byteLength) break;
      packets.push({ ts: sec + frac / (nano ? 1e9 : 1e6), data: new Uint8Array(buf, off, incl), origLen: orig, linktype });
      off += incl;
    }
    return { format: 'pcap', linktype, packets };
  }

  function readPcapng(buf) {
    const dv = new DataView(buf);
    let off = 0, le = true;
    const ifaces = [], packets = [];
    while (off + 12 <= buf.byteLength) {
      let type = dv.getUint32(off, le);
      if (type === 0x0a0d0d0a) {
        const bom = dv.getUint32(off + 8, true);
        le = bom === 0x1a2b3c4d;
        type = 0x0a0d0d0a;
      }
      const len = dv.getUint32(off + 4, le);
      if (len < 12 || off + len > buf.byteLength) break;
      if (type === 1) {                                   // Interface Description Block
        const link = dv.getUint16(off + 8, le);
        let tsres = 1e6;
        let o = off + 16;
        while (o + 4 <= off + len - 4) {                  // options : if_tsresol (code 9)
          const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le);
          if (code === 0) break;
          if (code === 9 && l >= 1) { const v = dv.getUint8(o + 4); tsres = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v; }
          o += 4 + Math.ceil(l / 4) * 4;
        }
        ifaces.push({ link, tsres });
      } else if (type === 6) {                            // Enhanced Packet Block
        const id = dv.getUint32(off + 8, le);
        const hi = dv.getUint32(off + 12, le), lo = dv.getUint32(off + 16, le);
        const cap = dv.getUint32(off + 20, le), orig = dv.getUint32(off + 24, le);
        const ifc = ifaces[id] || { link: 1, tsres: 1e6 };
        packets.push({ ts: (hi * 4294967296 + lo) / ifc.tsres, data: new Uint8Array(buf, off + 28, cap), origLen: orig, linktype: ifc.link });
      } else if (type === 3) {                            // Simple Packet Block
        const orig = dv.getUint32(off + 8, le), ifc = ifaces[0] || { link: 1 };
        const cap = Math.min(orig, len - 16);
        packets.push({ ts: 0, data: new Uint8Array(buf, off + 12, cap), origLen: orig, linktype: ifc.link });
      }
      off += len;
    }
    return { format: 'pcapng', linktype: ifaces[0] ? ifaces[0].link : 1, packets };
  }

  // ------------------------------------------------------------------
  //  Outils
  // ------------------------------------------------------------------
  const hex2 = (n) => n.toString(16).padStart(2, '0');
  const mac = (d, o) => Array.from(d.subarray(o, o + 6), hex2).join(':');
  const ip4 = (d, o) => d[o] + '.' + d[o + 1] + '.' + d[o + 2] + '.' + d[o + 3];
  function ip6(d, o) {
    const g = []; for (let i = 0; i < 16; i += 2) g.push(((d[o + i] << 8) | d[o + i + 1]).toString(16));
    let s = g.join(':'); const m = s.match(/(^|:)0(:0)+(:|$)/g);
    if (m) { const longest = m.reduce((a, b) => (b.length > a.length ? b : a)); s = s.replace(longest, '::'); }
    return s.replace(/:{3,}/, '::');
  }
  const u16 = (d, o) => (d[o] << 8) | d[o + 1];
  const u32 = (d, o) => ((d[o] << 24) >>> 0) + (d[o + 1] << 16) + (d[o + 2] << 8) + d[o + 3];
  const ascii = (d, o, l) => { let s = ''; for (let i = o; i < o + l && i < d.length; i++) s += String.fromCharCode(d[i]); return s; };

  // Somme de contrôle Internet (RFC 1071)
  function csum(d, o, l, init) {
    let s = init || 0;
    for (let i = 0; i + 1 < l; i += 2) s += (d[o + i] << 8) | d[o + i + 1];
    if (l & 1) s += d[o + l - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (~s) & 0xffff;
  }
  function pseudo4(d, ipo, proto, len) {
    let s = 0;
    for (let i = 0; i < 8; i += 2) s += (d[ipo + 12 + i] << 8) | d[ipo + 13 + i];
    return s + proto + len;
  }

  const ETHERTYPE = { 0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x8100: '802.1Q' };
  const IPPROTO = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 2: 'IGMP', 89: 'OSPF' };
  const PORTS = { 20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 104: 'DICOM', 110: 'POP3', 123: 'NTP', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 8080: 'HTTP' };
  const ICMP_T = { 0: 'Echo reply', 3: 'Destination unreachable', 5: 'Redirect', 8: 'Echo request', 11: 'Time exceeded' };
  const DNS_T = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY' };

  // Nœud de l'arbre de décodage
  const F = (name, value, off, len, children) => ({ name, value: value == null ? '' : String(value), off, len, children: children || null });

  // ------------------------------------------------------------------
  //  Décodage d'une trame
  // ------------------------------------------------------------------
  function dissect(pkt, index) {
    const d = pkt.data;
    const r = { index, ts: pkt.ts, len: pkt.origLen, caplen: d.length, tree: [], proto: 'Inconnu', src: '', dst: '', info: '', layers: [], flags: {} };
    r.tree.push(F('Trame ' + (index + 1), d.length + ' octets capturés (' + pkt.origLen + ' sur le câble)', 0, d.length));
    try {
      if (pkt.linktype === 1) ethernet(d, 0, r);
      else if (pkt.linktype === 101 || pkt.linktype === 228) ipv4(d, 0, r);
      else if (pkt.linktype === 229) ipv6(d, 0, r);
      else if (pkt.linktype === 113) sll(d, 0, r);
      else { r.info = 'Type de lien ' + pkt.linktype + ' non décodé'; }
    } catch (e) {
      r.tree.push(F('[Trame tronquée ou mal formée]', e.message, 0, 0));
      r.flags.malformed = true;
    }
    return r;
  }

  function sll(d, o, r) {
    const pt = u16(d, o + 14);
    r.tree.push(F('Linux cooked capture', 'protocole 0x' + pt.toString(16), o, 16));
    r.layers.push('SLL');
    afterEther(d, o + 16, pt, r);
  }

  function ethernet(d, o, r) {
    if (d.length < 14) throw new Error('en-tête Ethernet incomplet');
    const node = F('Ethernet II', 'src ' + mac(d, 6) + ', dst ' + mac(d, 0), o, 14, [
      F('Destination', mac(d, 0) + (d[0] === 0xff && d[1] === 0xff ? ' (diffusion)' : ''), 0, 6),
      F('Source', mac(d, 6), 6, 6),
      F('Type', '0x' + u16(d, 12).toString(16).padStart(4, '0') + ' (' + (ETHERTYPE[u16(d, 12)] || '?') + ')', 12, 2),
    ]);
    r.tree.push(node); r.layers.push('Ethernet');
    r.src = mac(d, 6); r.dst = mac(d, 0); r.proto = 'Ethernet';
    let et = u16(d, 12), p = 14;
    while (et === 0x8100 && p + 4 <= d.length) {         // 802.1Q
      const tci = u16(d, p), vid = tci & 0x0fff, pcp = tci >> 13;
      r.tree.push(F('802.1Q (VLAN)', 'VLAN ' + vid, p, 4, [F('Priorité (PCP)', pcp, p, 1), F('Identifiant de VLAN', vid, p, 2), F('Type', '0x' + u16(d, p + 2).toString(16).padStart(4, '0') + ' (' + (ETHERTYPE[u16(d, p + 2)] || '?') + ')', p + 2, 2)]));
      r.layers.push('802.1Q'); r.vlan = vid;
      et = u16(d, p + 2); p += 4;
    }
    afterEther(d, p, et, r);
  }
  function afterEther(d, p, et, r) {
    if (et === 0x0806) arp(d, p, r);
    else if (et === 0x0800) ipv4(d, p, r);
    else if (et === 0x86dd) ipv6(d, p, r);
    else r.info = 'Ethertype 0x' + et.toString(16);
  }

  function arp(d, o, r) {
    const op = u16(d, o + 6), sha = mac(d, o + 8), spa = ip4(d, o + 14), tha = mac(d, o + 18), tpa = ip4(d, o + 24);
    r.tree.push(F('ARP', op === 1 ? 'requête' : 'réponse', o, 28, [
      F('Opération', op + (op === 1 ? ' (requête)' : op === 2 ? ' (réponse)' : ''), o + 6, 2),
      F('MAC émetteur', sha, o + 8, 6), F('IP émetteur', spa, o + 14, 4),
      F('MAC cible', tha, o + 18, 6), F('IP cible', tpa, o + 24, 4),
    ]));
    r.layers.push('ARP'); r.proto = 'ARP'; r.arp = { op, sha, spa, tpa };
    r.info = op === 1 ? 'Qui a ' + tpa + ' ? Répondre à ' + spa : spa + ' est à ' + sha;
  }

  function ipv4(d, o, r) {
    const ihl = (d[o] & 0x0f) * 4, tot = u16(d, o + 2), proto = d[o + 9], ttl = d[o + 8];
    if (ihl < 20 || o + ihl > d.length) throw new Error('en-tête IPv4 incomplet');
    const flagsFrag = u16(d, o + 6), df = !!(flagsFrag & 0x4000), mf = !!(flagsFrag & 0x2000), frag = (flagsFrag & 0x1fff) * 8;
    const ck = u16(d, o + 10), ok = csum(d, o, ihl) === 0;
    const src = ip4(d, o + 12), dst = ip4(d, o + 16);
    r.tree.push(F('IPv4', src + ' → ' + dst, o, ihl, [
      F('Version', 4, o, 1), F('Longueur d\'en-tête', ihl + ' octets', o, 1), F('DSCP / ECN', '0x' + hex2(d[o + 1]), o + 1, 1),
      F('Longueur totale', tot, o + 2, 2), F('Identification', '0x' + u16(d, o + 4).toString(16).padStart(4, '0'), o + 4, 2),
      F('Drapeaux', (df ? 'DF ' : '') + (mf ? 'MF' : '') || 'aucun', o + 6, 1), F('Décalage de fragment', frag, o + 6, 2),
      F('TTL', ttl, o + 8, 1), F('Protocole', proto + ' (' + (IPPROTO[proto] || '?') + ')', o + 9, 1),
      F('Somme de contrôle', '0x' + ck.toString(16).padStart(4, '0') + (ok ? ' [correcte]' : ' [INCORRECTE]'), o + 10, 2),
      F('Source', src, o + 12, 4), F('Destination', dst, o + 16, 4),
    ]));
    r.layers.push('IPv4'); r.proto = 'IPv4'; r.src = src; r.dst = dst; r.ip = { src, dst, ttl, proto };
    if (!ok) r.flags.badIpCsum = true;
    const end = Math.min(d.length, o + tot);
    if (frag > 0 || mf) { r.info = 'Fragment IP (décalage ' + frag + ')'; return; }
    const p = o + ihl, plen = end - p;
    if (proto === 1) icmp(d, p, plen, r);
    else if (proto === 6) tcp(d, p, plen, r, o);
    else if (proto === 17) udp(d, p, plen, r, o);
    else { r.proto = IPPROTO[proto] || 'IPv4'; r.info = 'Protocole IP ' + proto; }
  }

  function ipv6(d, o, r) {
    const plen = u16(d, o + 4), nh = d[o + 6], hl = d[o + 7], src = ip6(d, o + 8), dst = ip6(d, o + 24);
    r.tree.push(F('IPv6', src + ' → ' + dst, o, 40, [F('Longueur des données', plen, o + 4, 2), F('En-tête suivant', nh + ' (' + (IPPROTO[nh] || '?') + ')', o + 6, 1), F('Limite de sauts', hl, o + 7, 1), F('Source', src, o + 8, 16), F('Destination', dst, o + 24, 16)]));
    r.layers.push('IPv6'); r.proto = 'IPv6'; r.src = src; r.dst = dst; r.ip = { src, dst, ttl: hl, proto: nh, v6: true };
    const p = o + 40, len = Math.min(plen, d.length - p);
    if (nh === 6) tcp(d, p, len, r, -1);
    else if (nh === 17) udp(d, p, len, r, -1);
    else if (nh === 58) { r.proto = 'ICMPv6'; r.layers.push('ICMPv6'); r.tree.push(F('ICMPv6', 'type ' + d[p], p, len)); r.info = 'ICMPv6 type ' + d[p]; }
    else r.info = 'En-tête suivant ' + nh;
  }

  function icmp(d, o, len, r) {
    const type = d[o], code = d[o + 1], ok = csum(d, o, len) === 0;
    const kids = [F('Type', type + ' (' + (ICMP_T[type] || '?') + ')', o, 1), F('Code', code, o + 1, 1), F('Somme de contrôle', '0x' + u16(d, o + 2).toString(16).padStart(4, '0') + (ok ? ' [correcte]' : ' [INCORRECTE]'), o + 2, 2)];
    let info = ICMP_T[type] || 'ICMP type ' + type;
    if (type === 0 || type === 8) {
      const id = u16(d, o + 4), seq = u16(d, o + 6);
      kids.push(F('Identifiant', '0x' + id.toString(16).padStart(4, '0'), o + 4, 2), F('Numéro de séquence', seq, o + 6, 2), F('Données', (len - 8) + ' octets', o + 8, len - 8));
      info += ' (id=0x' + id.toString(16).padStart(4, '0') + ', seq=' + seq + ', ttl=' + r.ip.ttl + ')';
      r.icmp = { type, id, seq };
    } else if (type === 3) info += ' (code ' + code + ')';
    r.tree.push(F('ICMP', ICMP_T[type] || type, o, len, kids));
    r.layers.push('ICMP'); r.proto = 'ICMP'; r.info = info;
    if (!ok) r.flags.badCsum = true;
  }

  const TCPF = [['FIN', 0x01], ['SYN', 0x02], ['RST', 0x04], ['PSH', 0x08], ['ACK', 0x10], ['URG', 0x20], ['ECE', 0x40], ['CWR', 0x80]];
  function tcp(d, o, len, r, ipo) {
    if (len < 20) throw new Error('en-tête TCP incomplet');
    const sp = u16(d, o), dp = u16(d, o + 2), seq = u32(d, o + 4), ack = u32(d, o + 8), hl = (d[o + 12] >> 4) * 4, fl = d[o + 13], win = u16(d, o + 14);
    const names = TCPF.filter(([, b]) => fl & b).map(([n]) => n);
    let ckTxt = '0x' + u16(d, o + 16).toString(16).padStart(4, '0'), ok = true;
    if (ipo >= 0) { ok = csum(d, o, len, pseudo4(d, ipo, 6, len)) === 0; ckTxt += ok ? ' [correcte]' : ' [INCORRECTE]'; }
    const opts = [], optNodes = [];
    for (let p = o + 20; p < o + hl;) {
      const k = d[p];
      if (k === 0) break;
      if (k === 1) { p++; continue; }
      const l = d[p + 1] || 2;
      if (k === 2) { opts.push('MSS=' + u16(d, p + 2)); optNodes.push(F('MSS', u16(d, p + 2), p, l)); }
      else if (k === 3) { opts.push('WS=' + (1 << d[p + 2])); optNodes.push(F('Facteur d\'échelle de fenêtre', d[p + 2] + ' (×' + (1 << d[p + 2]) + ')', p, l)); }
      else if (k === 4) { opts.push('SACK_PERM'); optNodes.push(F('SACK autorisé', '', p, l)); }
      else if (k === 8) { optNodes.push(F('Horodatage', 'TSval ' + u32(d, p + 2) + ', TSecr ' + u32(d, p + 6), p, l)); }
      else optNodes.push(F('Option ' + k, l + ' octets', p, l));
      p += l;
    }
    const payload = len - hl;
    const kids = [F('Port source', sp, o, 2), F('Port destination', dp, o + 2, 2), F('Numéro de séquence', seq, o + 4, 4), F('Numéro d\'acquittement', ack, o + 8, 4),
      F('Longueur d\'en-tête', hl + ' octets', o + 12, 1), F('Drapeaux', names.join(', ') || 'aucun', o + 13, 1), F('Fenêtre', win, o + 14, 2), F('Somme de contrôle', ckTxt, o + 16, 2)];
    if (optNodes.length) kids.push(F('Options', optNodes.length, o + 20, hl - 20, optNodes));
    if (payload > 0) kids.push(F('Données', payload + ' octets', o + hl, payload));
    r.tree.push(F('TCP', sp + ' → ' + dp + ' [' + names.join(', ') + ']', o, hl, kids));
    r.layers.push('TCP'); r.proto = 'TCP';
    r.tcp = { sp, dp, seq, ack, flags: fl, names, win, payload, dataOff: o + hl };
    if (!ok) r.flags.badCsum = true;
    r.info = sp + ' → ' + dp + ' [' + names.join(', ') + '] Seq=' + seq + (fl & 0x10 ? ' Ack=' + ack : '') + ' Win=' + win + ' Len=' + payload + (opts.length ? ' ' + opts.join(' ') : '');
    if (payload > 0) application(d, o + hl, payload, sp, dp, r, 'tcp');
  }

  function udp(d, o, len, r, ipo) {
    const sp = u16(d, o), dp = u16(d, o + 2), ul = u16(d, o + 4), ck = u16(d, o + 6);
    let ckTxt = '0x' + ck.toString(16).padStart(4, '0'), ok = true;
    if (ipo >= 0 && ck !== 0) { ok = csum(d, o, ul, pseudo4(d, ipo, 17, ul)) === 0; ckTxt += ok ? ' [correcte]' : ' [INCORRECTE]'; }
    else if (ck === 0) ckTxt += ' [non calculée]';
    r.tree.push(F('UDP', sp + ' → ' + dp, o, 8, [F('Port source', sp, o, 2), F('Port destination', dp, o + 2, 2), F('Longueur', ul, o + 4, 2), F('Somme de contrôle', ckTxt, o + 6, 2)]));
    r.layers.push('UDP'); r.proto = 'UDP'; r.udp = { sp, dp };
    if (!ok) r.flags.badCsum = true;
    r.info = sp + ' → ' + dp + ' Len=' + (ul - 8);
    if (ul > 8) application(d, o + 8, Math.min(ul - 8, d.length - o - 8), sp, dp, r, 'udp');
  }

  // ------------------------------------------------------------------
  //  Couche application
  // ------------------------------------------------------------------
  function application(d, o, len, sp, dp, r, l4) {
    const port = (p) => sp === p || dp === p;
    if (port(53)) return dns(d, o, len, r, l4 === 'tcp');
    if (l4 === 'tcp' && (port(80) || port(8080))) return http(d, o, len, r);
    if (l4 === 'tcp' && port(443)) return tls(d, o, len, r);
    if (l4 === 'tcp' && port(21)) return lineProto(d, o, len, r, 'FTP');
    if (l4 === 'tcp' && port(23)) return lineProto(d, o, len, r, 'Telnet');
    const name = PORTS[dp] || PORTS[sp];
    if (name) { r.proto = name; r.info = name + ' · ' + r.info; }
  }

  function dnsName(d, base, p, depth) {
    const labels = [];
    let jumped = false, end = p, guard = 0;
    while (p < d.length && guard++ < 64) {
      const l = d[p];
      if (l === 0) { if (!jumped) end = p + 1; break; }
      if ((l & 0xc0) === 0xc0) { if (!jumped) end = p + 2; p = base + (((l & 0x3f) << 8) | d[p + 1]); jumped = true; if ((depth || 0) > 8) break; continue; }
      labels.push(ascii(d, p + 1, l)); p += l + 1;
    }
    return { name: labels.join('.') || '<racine>', end };
  }
  function dns(d, o, len, r, overTcp) {
    if (overTcp) { o += 2; len -= 2; }
    if (len < 12) return;
    const id = u16(d, o), fl = u16(d, o + 2), qd = u16(d, o + 4), an = u16(d, o + 6), isResp = !!(fl & 0x8000), rcode = fl & 0x0f;
    const kids = [F('Identifiant de transaction', '0x' + id.toString(16).padStart(4, '0'), o, 2), F('Drapeaux', (isResp ? 'réponse' : 'requête') + ', code ' + rcode + (rcode === 3 ? ' (nom inexistant)' : ''), o + 2, 2), F('Questions', qd, o + 4, 2), F('Réponses', an, o + 6, 2)];
    let p = o + 12; const qs = [], ans = [];
    for (let i = 0; i < qd && p < o + len; i++) {
      const n = dnsName(d, o, p); const t = u16(d, n.end);
      qs.push(n.name + ' ' + (DNS_T[t] || t)); kids.push(F('Question', n.name + ' (type ' + (DNS_T[t] || t) + ')', p, n.end + 4 - p)); p = n.end + 4;
    }
    for (let i = 0; i < an && p < o + len; i++) {
      const n = dnsName(d, o, p); const t = u16(d, n.end), ttl = u32(d, n.end + 4), rl = u16(d, n.end + 8), rd = n.end + 10;
      let v = rl + ' octets';
      if (t === 1 && rl === 4) v = ip4(d, rd); else if (t === 28 && rl === 16) v = ip6(d, rd); else if (t === 5 || t === 12 || t === 2) v = dnsName(d, o, rd).name;
      ans.push((DNS_T[t] || t) + ' ' + v); kids.push(F('Réponse', n.name + ' ' + (DNS_T[t] || t) + ' ' + v + ' (TTL ' + ttl + ' s)', p, rd + rl - p)); p = rd + rl;
    }
    r.tree.push(F('DNS', isResp ? 'réponse' : 'requête', o, len, kids));
    r.layers.push('DNS'); r.proto = 'DNS'; r.dns = { id, isResp, qs, ans, rcode };
    r.info = (isResp ? 'Réponse' : 'Requête') + ' 0x' + id.toString(16).padStart(4, '0') + ' ' + qs.join(', ') + (ans.length ? ' → ' + ans.join(', ') : '') + (rcode === 3 ? ' (inexistant)' : '');
  }

  function http(d, o, len, r) {
    const txt = ascii(d, o, len);
    const head = txt.split('\r\n\r\n')[0], lines = head.split('\r\n');
    if (!/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) |^HTTP\/1\.[01] /.test(lines[0])) { r.proto = 'HTTP'; r.info = 'HTTP (suite des données)'; return; }
    const kids = []; let p = o;
    for (const l of lines) { kids.push(F(l.length > 80 ? l.slice(0, 80) + '…' : l, '', p, l.length + 2)); p += l.length + 2; }
    r.tree.push(F('HTTP', lines[0], o, len, kids));
    r.layers.push('HTTP'); r.proto = 'HTTP'; r.info = lines[0];
    const auth = lines.find((l) => /^authorization:\s*basic\s+/i.test(l));
    if (auth) {
      let dec = '';
      try { dec = (typeof atob === 'function' ? atob : (s) => Buffer.from(s, 'base64').toString('binary'))(auth.replace(/^authorization:\s*basic\s+/i, '').trim()); } catch (e) { dec = '?'; }
      r.cleartext = { proto: 'HTTP (authentification Basic)', value: dec };
    }
    const form = txt.split('\r\n\r\n')[1] || '';
    if (/^POST /.test(lines[0]) && /(pass|pwd|mot_?de_?passe)=/i.test(form)) r.cleartext = { proto: 'HTTP (formulaire)', value: form.slice(0, 80) };
  }

  function tls(d, o, len, r) {
    const ct = d[o], ver = u16(d, o + 1);
    const CT = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'Données applicatives' };
    const VER = { 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
    if (!CT[ct] || (ver >> 8) !== 3) { r.proto = 'TLS'; r.info = 'TLS (suite)'; return; }
    const kids = [F('Type de contenu', ct + ' (' + CT[ct] + ')', o, 1), F('Version', VER[ver] || ver, o + 1, 2), F('Longueur', u16(d, o + 3), o + 3, 2)];
    let info = CT[ct];
    if (ct === 22 && d[o + 5] === 1) {                   // ClientHello : recherche de l'extension SNI
      info = 'Client Hello';
      let p = o + 5 + 4 + 2 + 32;
      p += 1 + d[p];                                      // session id
      p += 2 + u16(d, p);                                 // suites
      p += 1 + d[p];                                      // compression
      const extEnd = p + 2 + u16(d, p); p += 2;
      while (p + 4 <= extEnd && p + 4 <= o + len) {
        const et = u16(d, p), el = u16(d, p + 2);
        if (et === 0) { const nl = u16(d, p + 7); const sni = ascii(d, p + 9, nl); kids.push(F('Nom du serveur (SNI)', sni, p + 9, nl)); info += ' (SNI=' + sni + ')'; r.sni = sni; }
        p += 4 + el;
      }
    } else if (ct === 22 && d[o + 5] === 2) info = 'Server Hello';
    r.tree.push(F('TLS', info, o, len, kids));
    r.layers.push('TLS'); r.proto = 'TLS'; r.info = info;
  }

  function lineProto(d, o, len, r, name) {
    const txt = ascii(d, o, len).replace(/\r?\n$/, '');
    r.tree.push(F(name, txt.length > 60 ? txt.slice(0, 60) + '…' : txt, o, len));
    r.layers.push(name); r.proto = name; r.info = name + ' : ' + txt.replace(/\r?\n/g, ' ⏎ ').slice(0, 80);
    const m = /^(USER|PASS)\s+(.*)$/i.exec(txt.trim());
    if (m) r.cleartext = { proto: name, value: m[1].toUpperCase() + ' ' + m[2], field: m[1].toUpperCase() };
  }

  // ------------------------------------------------------------------
  //  Analyse de l'ensemble de la capture
  // ------------------------------------------------------------------
  function analyse(list) {
    const alerts = [], protoCount = {}, convs = new Map(), streams = new Map(), seen = new Map(), syns = new Map();
    let bytes = 0;
    list.forEach((p) => {
      bytes += p.len;
      const top = p.proto; protoCount[top] = (protoCount[top] || 0) + 1;
      if (p.flags.badIpCsum || p.flags.badCsum) alerts.push({ lvl: 'warn', code: 'csum', pkt: p.index });
      if (p.ip) {
        const a = p.ip.src, b = p.ip.dst, key = a < b ? a + '|' + b : b + '|' + a;
        const c = convs.get(key) || { a: a < b ? a : b, b: a < b ? b : a, pkts: 0, bytes: 0 };
        c.pkts++; c.bytes += p.len; convs.set(key, c);
      }
      if (p.tcp) {
        const t = p.tcp, A = p.ip.src + ':' + t.sp, B = p.ip.dst + ':' + t.dp;
        const key = A < B ? A + '|' + B : B + '|' + A;
        let s = streams.get(key);
        if (!s) { s = { id: streams.size, client: null, server: null, syn: false, synack: false, ack: false, rst: false, fin: 0, pkts: 0, first: p.index }; streams.set(key, s); }
        s.pkts++; p.stream = s.id;
        if ((t.flags & 0x12) === 0x02) { s.syn = true; s.client = A; s.server = B; }
        else if ((t.flags & 0x12) === 0x12 && s.syn) s.synack = true;
        else if ((t.flags & 0x10) && s.synack && !s.ack && A === s.client) { s.ack = true; p.handshakeDone = true; }
        if (t.flags & 0x04) { s.rst = true; }
        if (t.flags & 0x01) s.fin++;
        // retransmission : même sens, même numéro de séquence, des données déjà vues
        if (t.payload > 0 || (t.flags & 0x03)) {
          const rk = A + '>' + B + '#' + t.seq + '#' + t.payload + '#' + (t.flags & 0x03);
          if (seen.has(rk)) { p.retrans = seen.get(rk); alerts.push({ lvl: 'warn', code: 'retrans', pkt: p.index, of: seen.get(rk) }); }
          else seen.set(rk, p.index);
        }
        // scan de ports : SYN seuls d'une même source vers beaucoup de ports
        if ((t.flags & 0x12) === 0x02) {
          const sk = p.ip.src + '>' + p.ip.dst; const set = syns.get(sk) || new Set(); set.add(t.dp); syns.set(sk, set);
        }
      }
      if (p.cleartext) alerts.push({ lvl: 'err', code: 'clear', pkt: p.index, proto: p.cleartext.proto, value: p.cleartext.value });
      if (p.proto === 'Telnet' && !p.cleartext) p.flags.telnet = true;
      if (p.dns && p.dns.isResp && p.dns.rcode === 3) alerts.push({ lvl: 'info', code: 'nxdomain', pkt: p.index, value: p.dns.qs.join(', ') });
    });
    syns.forEach((ports, sk) => { if (ports.size >= 10) { const [src, dst] = sk.split('>'); alerts.push({ lvl: 'err', code: 'scan', src, dst, n: ports.size, ports: [...ports].sort((x, y) => x - y) }); } });
    const handshakes = [...streams.values()].filter((s) => s.syn && s.synack && s.ack).length;
    const resets = [...streams.values()].filter((s) => s.rst).length;
    const unanswered = [...streams.values()].filter((s) => s.syn && !s.synack && !s.rst).length;
    const dur = list.length ? list[list.length - 1].ts - list[0].ts : 0;
    return {
      alerts, protoCount, bytes, duration: dur, handshakes, resets, unanswered, streams: streams.size,
      convs: [...convs.values()].sort((x, y) => y.bytes - x.bytes),
    };
  }

  // ------------------------------------------------------------------
  //  Filtre d'affichage (sous-ensemble de la syntaxe Wireshark)
  //  ex. : tcp · dns · arp · ip.addr == 10.0.0.1 · tcp.port == 443 · vlan == 10
  //        combinés avec and / or / not, et des parenthèses
  // ------------------------------------------------------------------
  function compileFilter(src) {
    const s = String(src || '').trim();
    if (!s) return () => true;
    const toks = s.match(/\(|\)|==|!=|&&|\|\||!|[^\s()=!&|]+/g) || [];
    let i = 0;
    const peek = () => toks[i], next = () => toks[i++];
    function prim() {
      const t = next();
      if (t === undefined) throw new Error('filtre incomplet');
      if (t === '(') { const e = or(); if (next() !== ')') throw new Error('parenthèse manquante'); return e; }
      if (t === 'not' || t === '!') { const e = prim(); return (p) => !e(p); }
      const field = t.toLowerCase();
      if (peek() === '==' || peek() === '!=') {
        const op = next(), val = next();
        if (val === undefined) throw new Error('valeur manquante');
        const get = FIELDS[field];
        if (!get) throw new Error('champ inconnu : ' + t);
        const test = (p) => get(p).some((v) => String(v).toLowerCase() === val.toLowerCase());
        return op === '==' ? test : (p) => !test(p);
      }
      const proto = field;
      return (p) => p.layers.some((l) => l.toLowerCase() === proto) || p.proto.toLowerCase() === proto || (proto === 'ip' && !!p.ip && !p.ip.v6) || (proto === 'vlan' && p.vlan != null);
    }
    function and() { let e = prim(); while (peek() === 'and' || peek() === '&&') { next(); const a = e, b = prim(); e = (p) => a(p) && b(p); } return e; }
    function or() { let e = and(); while (peek() === 'or' || peek() === '||') { next(); const a = e, b = and(); e = (p) => a(p) || b(p); } return e; }
    const f = or();
    if (i < toks.length) throw new Error('élément inattendu : ' + toks[i]);
    return f;
  }
  const FIELDS = {
    'ip.addr': (p) => (p.ip ? [p.ip.src, p.ip.dst] : p.arp ? [p.arp.spa, p.arp.tpa] : []),
    'ip.src': (p) => (p.ip ? [p.ip.src] : []), 'ip.dst': (p) => (p.ip ? [p.ip.dst] : []),
    'tcp.port': (p) => (p.tcp ? [p.tcp.sp, p.tcp.dp] : []), 'udp.port': (p) => (p.udp ? [p.udp.sp, p.udp.dp] : []),
    'port': (p) => (p.tcp ? [p.tcp.sp, p.tcp.dp] : p.udp ? [p.udp.sp, p.udp.dp] : []),
    'tcp.stream': (p) => (p.stream != null ? [p.stream] : []), 'vlan': (p) => (p.vlan != null ? [p.vlan] : []), 'vlan.id': (p) => (p.vlan != null ? [p.vlan] : []),
    'frame.number': (p) => [p.index + 1],
  };

  function load(buf) {
    const cap = readPcap(buf);
    const list = cap.packets.map((p, i) => dissect(p, i));
    return { cap, list, stats: analyse(list) };
  }

  const api = { readPcap, dissect, analyse, compileFilter, load, csum, LINK };
  root.PcapAnalyser = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
