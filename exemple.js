// =====================================================================
//  Génération d'une capture d'exemple (fichier pcap), octet par octet,
//  avec des sommes de contrôle valides. Scénario FICTIF inspiré du plan
//  d'adressage du PoC de téléradiologie : un poste du site de Paris
//  (VLAN 10) consulte la plateforme web de la DMZ, et une VM de
//  l'extranet radiologues balaie les ports du serveur.
//  Identifiants de démonstration uniquement (aucun vrai mot de passe).
// =====================================================================
(function (root) {
  'use strict';

  const MAC = { pc: '00:50:79:66:68:10', gw: 'c2:01:0a:3c:00:10', fwradio: 'c2:04:11:20:00:03', vmradio: '08:00:27:4e:52:11' };
  const IP = { pc: '172.16.10.10', gw: '172.16.10.1', web: '192.168.101.10', dns: '192.168.101.53', radio: '192.168.11.10' };

  const bytesMac = (m) => m.split(':').map((h) => parseInt(h, 16));
  const bytesIp = (s) => s.split('.').map(Number);
  const be16 = (n) => [(n >> 8) & 255, n & 255];
  const be32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const str = (s) => Array.from(s, (c) => c.charCodeAt(0) & 255);

  function csum(arr, init) {
    let s = init || 0;
    for (let i = 0; i + 1 < arr.length; i += 2) s += (arr[i] << 8) | arr[i + 1];
    if (arr.length & 1) s += arr[arr.length - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (~s) & 0xffff;
  }

  function eth(dst, src, type, payload, vlan) {
    const h = [...bytesMac(dst), ...bytesMac(src)];
    if (vlan != null) h.push(0x81, 0x00, ...be16(vlan & 0x0fff));
    return [...h, ...be16(type), ...payload];
  }
  let ipId = 0x1c46;
  function ipv4(src, dst, proto, payload, ttl) {
    const tot = 20 + payload.length;
    const h = [0x45, 0, ...be16(tot), ...be16(ipId++ & 0xffff), 0x40, 0, ttl || 64, proto, 0, 0, ...bytesIp(src), ...bytesIp(dst)];
    const c = csum(h); h[10] = c >> 8; h[11] = c & 255;
    return [...h, ...payload];
  }
  function pseudo(src, dst, proto, len) {
    const a = [...bytesIp(src), ...bytesIp(dst)];
    let s = 0; for (let i = 0; i < 8; i += 2) s += (a[i] << 8) | a[i + 1];
    return s + proto + len;
  }
  function tcpSeg(src, dst, sp, dp, seq, ack, flags, payload, opts, win) {
    const o = opts || [];
    const hl = 20 + o.length;
    const seg = [...be16(sp), ...be16(dp), ...be32(seq >>> 0), ...be32(ack >>> 0), (hl / 4) << 4, flags, ...be16(win == null ? 64240 : win), 0, 0, 0, 0, ...o, ...(payload || [])];
    const c = csum(seg, pseudo(src, dst, 6, seg.length)); seg[16] = c >> 8; seg[17] = c & 255;
    return seg;
  }
  function udpDgram(src, dst, sp, dp, payload) {
    const len = 8 + payload.length;
    const d = [...be16(sp), ...be16(dp), ...be16(len), 0, 0, ...payload];
    const c = csum(d, pseudo(src, dst, 17, len)) || 0xffff; d[6] = c >> 8; d[7] = c & 255;
    return d;
  }
  function icmpEcho(type, id, seq) {
    const data = str('abcdefghijklmnopqrstuvwabcdefghi');
    const m = [type, 0, 0, 0, ...be16(id), ...be16(seq), ...data];
    const c = csum(m); m[2] = c >> 8; m[3] = c & 255;
    return m;
  }
  function dnsMsg(id, resp, name, answerIp, rcode) {
    const q = []; name.split('.').forEach((l) => { q.push(l.length, ...str(l)); }); q.push(0, 0, 1, 0, 1);
    const flags = resp ? 0x8180 | (rcode || 0) : 0x0100;
    const an = resp && answerIp ? 1 : 0;
    const m = [...be16(id), ...be16(flags), 0, 1, 0, an, 0, 0, 0, 0, ...q];
    if (an) m.push(0xc0, 0x0c, 0, 1, 0, 1, ...be32(300), 0, 4, ...bytesIp(answerIp));
    return m;
  }
  function clientHello(sni) {
    const name = str(sni);
    const sniExt = [0, 0, ...be16(name.length + 5), ...be16(name.length + 3), 0, ...be16(name.length), ...name];
    const suites = [0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 0xc0, 0x30];
    const body = [0x03, 0x03, ...new Array(32).fill(0).map((_, i) => (i * 37 + 11) & 255), 0, ...be16(suites.length), ...suites, 1, 0, ...be16(sniExt.length), ...sniExt];
    const hs = [1, 0, ...be16(body.length), ...body];
    return [22, 0x03, 0x01, ...be16(hs.length), ...hs];
  }
  function serverHello() {
    const body = [0x03, 0x03, ...new Array(32).fill(0).map((_, i) => (i * 53 + 7) & 255), 0, 0x13, 0x01, 0, 0, 0];
    const hs = [2, 0, ...be16(body.length), ...body];
    return [22, 0x03, 0x03, ...be16(hs.length), ...hs];
  }
  const OPTS_SYN = [2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 0, 0];           // MSS 1460, NOP, WS 7, SACK perm, fin

  function build() {
    ipId = 0x1c46;
    const frames = [];
    let t = 1730000000.0;                      // horodatage de départ fictif
    const add = (bytes, dt) => { t += dt || 0.0004; frames.push({ ts: t, data: bytes }); };
    const fromPc = (dstMac, payloadIp) => eth(dstMac, MAC.pc, 0x0800, payloadIp, 10);
    const toPc = (payloadIp) => eth(MAC.pc, MAC.gw, 0x0800, payloadIp, 10);

    // 1-2. ARP : le poste cherche sa passerelle
    add(eth('ff:ff:ff:ff:ff:ff', MAC.pc, 0x0806, [0, 1, 8, 0, 6, 4, 0, 1, ...bytesMac(MAC.pc), ...bytesIp(IP.pc), 0, 0, 0, 0, 0, 0, ...bytesIp(IP.gw)], 10), 0);
    add(eth(MAC.pc, MAC.gw, 0x0806, [0, 1, 8, 0, 6, 4, 0, 2, ...bytesMac(MAC.gw), ...bytesIp(IP.gw), ...bytesMac(MAC.pc), ...bytesIp(IP.pc)], 10), 0.0012);
    // 3-6. ping vers le serveur web de la DMZ (passe par R-Paris et le pare-feu : TTL 62 au retour)
    for (let s = 1; s <= 2; s++) {
      add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 1, icmpEcho(8, 0x0d21, s), 64)), s === 1 ? 0.21 : 1.0);
      add(toPc(ipv4(IP.web, IP.pc, 1, icmpEcho(0, 0x0d21, s), 62)), 0.0031);
    }
    // 7-8. DNS : résolution du nom de la plateforme
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.dns, 17, udpDgram(IP.pc, IP.dns, 53211, 53, dnsMsg(0x5a3c, false, 'telerad.demo')))), 0.8);
    add(toPc(ipv4(IP.dns, IP.pc, 17, udpDgram(IP.dns, IP.pc, 53, 53211, dnsMsg(0x5a3c, true, 'telerad.demo', IP.web)), 62)), 0.0024);
    // 9-13. HTTPS : poignée de main TCP puis TLS ClientHello / ServerHello
    let c = 1000000, s = 3000000;
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51000, 443, c, 0, 0x02, [], OPTS_SYN))), 0.01);
    add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 443, 51000, s, c + 1, 0x12, [], OPTS_SYN, 65160), 62)), 0.0029);
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51000, 443, c + 1, s + 1, 0x10, []))), 0.0002);
    const ch = clientHello('telerad.demo');
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51000, 443, c + 1, s + 1, 0x18, ch))), 0.0011);
    const sh = serverHello();
    add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 443, 51000, s + 1, c + 1 + ch.length, 0x18, sh, [], 65160), 62)), 0.0034);
    // 14-19. HTTP en clair avec authentification Basic (identifiants de démonstration), puis retransmission
    c = 2000000; s = 4000000;
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51002, 80, c, 0, 0x02, [], OPTS_SYN))), 0.6);
    add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 80, 51002, s, c + 1, 0x12, [], OPTS_SYN, 65160), 62)), 0.0027);
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51002, 80, c + 1, s + 1, 0x10, []))), 0.0002);
    const get = str('GET /espace-radiologue HTTP/1.1\r\nHost: telerad.demo\r\nUser-Agent: Mozilla/5.0\r\nAuthorization: Basic ' + btoa64('radiologue.demo:demo1234') + '\r\nAccept: */*\r\n\r\n');
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51002, 80, c + 1, s + 1, 0x18, get))), 0.0009);
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51002, 80, c + 1, s + 1, 0x18, get))), 0.2);   // retransmission (pas d'ACK reçu à temps)
    const resp = str('HTTP/1.1 302 Found\r\nLocation: https://telerad.demo/espace-radiologue\r\nContent-Length: 0\r\n\r\n');
    add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 80, 51002, s + 1, c + 1 + get.length, 0x18, resp, [], 65160), 62)), 0.0031);
    // 20-27. FTP : identifiants envoyés en clair
    c = 5000000; s = 6000000;
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51004, 21, c, 0, 0x02, [], OPTS_SYN))), 0.9);
    add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 21, 51004, s, c + 1, 0x12, [], OPTS_SYN, 65160), 62)), 0.0026);
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51004, 21, c + 1, s + 1, 0x10, []))), 0.0002);
    const ftpLines = [['srv', '220 Serveur FTP de demonstration\r\n'], ['cli', 'USER depot.demo\r\n'], ['srv', '331 Mot de passe requis\r\n'], ['cli', 'PASS demo1234\r\n'], ['srv', '230 Connexion reussie\r\n']];
    let cs = c + 1, ss = s + 1;
    for (const [who, line] of ftpLines) {
      const b = str(line);
      if (who === 'srv') { add(toPc(ipv4(IP.web, IP.pc, 6, tcpSeg(IP.web, IP.pc, 21, 51004, ss, cs, 0x18, b, [], 65160), 62)), 0.004); ss += b.length; }
      else { add(fromPc(MAC.gw, ipv4(IP.pc, IP.web, 6, tcpSeg(IP.pc, IP.web, 51004, 21, cs, ss, 0x18, b))), 0.3); cs += b.length; }
    }
    // 28. DNS : nom inexistant
    add(fromPc(MAC.gw, ipv4(IP.pc, IP.dns, 17, udpDgram(IP.pc, IP.dns, 53212, 53, dnsMsg(0x5a3d, false, 'pacs.demo')))), 0.5);
    add(toPc(ipv4(IP.dns, IP.pc, 17, udpDgram(IP.dns, IP.pc, 53, 53212, dnsMsg(0x5a3d, true, 'pacs.demo', null, 3)), 62)), 0.0022);
    // scan de ports depuis la VM de l'extranet radiologues (SYN, puis RST des ports fermés, SYN-ACK du 443)
    const ports = [21, 22, 23, 25, 53, 80, 104, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080];
    let sq = 777000;
    const fromRadio = (ipPayload) => eth(MAC.fwradio, MAC.vmradio, 0x0800, ipPayload);
    const toRadio = (ipPayload) => eth(MAC.vmradio, MAC.fwradio, 0x0800, ipPayload);
    ports.forEach((p, k) => {
      add(fromRadio(ipv4(IP.radio, IP.web, 6, tcpSeg(IP.radio, IP.web, 40000 + k, p, sq, 0, 0x02, [], [2, 4, 0x05, 0xb4], 1024))), k ? 0.0008 : 1.2);
      const open = p === 443 || p === 80 || p === 21;
      add(toRadio(ipv4(IP.web, IP.radio, 6, tcpSeg(IP.web, IP.radio, p, 40000 + k, open ? 9000000 + k : 0, sq + 1, open ? 0x12 : 0x14, [], open ? [2, 4, 0x05, 0xb4] : [], open ? 65160 : 0), 63)), 0.0011);
      if (open) add(fromRadio(ipv4(IP.radio, IP.web, 6, tcpSeg(IP.radio, IP.web, 40000 + k, p, sq + 1, 0, 0x04, [], [], 0))), 0.0001);
    });
    return frames;
  }
  function btoa64(s) {
    if (typeof btoa === 'function') return btoa(s);
    return Buffer.from(s, 'binary').toString('base64');
  }

  // Écriture du fichier pcap (petit-boutiste, microsecondes, Ethernet)
  function toPcap(frames) {
    const total = 24 + frames.reduce((a, f) => a + 16 + f.data.length, 0);
    const buf = new ArrayBuffer(total), dv = new DataView(buf), u8 = new Uint8Array(buf);
    dv.setUint32(0, 0xa1b2c3d4, true); dv.setUint16(4, 2, true); dv.setUint16(6, 4, true); dv.setUint32(16, 65535, true); dv.setUint32(20, 1, true);
    let o = 24;
    for (const f of frames) {
      const sec = Math.floor(f.ts), us = Math.round((f.ts - sec) * 1e6);
      dv.setUint32(o, sec, true); dv.setUint32(o + 4, us, true); dv.setUint32(o + 8, f.data.length, true); dv.setUint32(o + 12, f.data.length, true);
      u8.set(f.data, o + 16); o += 16 + f.data.length;
    }
    return buf;
  }

  const api = { build, toPcap, IP, MAC };
  root.ExempleCapture = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
