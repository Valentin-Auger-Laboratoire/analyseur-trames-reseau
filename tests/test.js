// Tests de l'analyseur de trames : node tests/test.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const P = require('../pcap.js');
const E = require('../exemple.js');
const dir = path.join(__dirname, 'donnees');
const ab = (b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.length);

// 1. Somme de contrôle Internet : en-tête IPv4 de l'exemple classique (RFC 1071), somme attendue 0xb861
const hdr = Uint8Array.from([0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7]);
assert.strictEqual(P.csum(hdr, 0, 20), 0xb861);

// 2. Captures de référence écrites par Scapy (outil indépendant) : 300 paquets aléatoires,
//    en pcap et en pcapng. Adresses, ports, séquences, réponses DNS, VLAN et sommes de contrôle doivent concorder.
const ref = JSON.parse(fs.readFileSync(path.join(dir, 'ref.json'), 'utf8'));
for (const f of ['ref.pcap', 'ref.pcapng']) {
  const r = P.load(ab(fs.readFileSync(path.join(dir, f))));
  assert.strictEqual(r.list.length, ref.length, f + ' : nombre de paquets');
  r.list.forEach((p, i) => {
    const e = ref[i], l4 = p.tcp || p.udp;
    assert.strictEqual(p.src, e.src, f + ' #' + i + ' source');
    assert.strictEqual(p.dst, e.dst, f + ' #' + i + ' destination');
    if (e.sp) { assert.strictEqual(l4.sp, e.sp); assert.strictEqual(l4.dp, e.dp); }
    if (e.seq != null) assert.strictEqual(p.tcp.seq, e.seq);
    if (e.ans) assert.strictEqual(p.dns.ans[0], 'A ' + e.ans);
    if (e.vlan != null) assert.strictEqual(p.vlan, e.vlan);
    assert.ok(!p.flags.badCsum && !p.flags.badIpCsum, f + ' #' + i + ' somme de contrôle');
  });
}

// 3. Capture d'exemple : contenu attendu et analyse
const r = P.load(E.toPcap(E.build()));
assert.strictEqual(r.list.length, 64);
assert.ok(r.list.every((p) => !p.flags.badCsum && !p.flags.badIpCsum), 'toutes les sommes de contrôle sont valides');
assert.strictEqual(r.list[0].proto, 'ARP');
assert.strictEqual(r.list[0].vlan, 10);
assert.strictEqual(r.list[7].dns.ans[0], 'A 192.168.101.10');
assert.strictEqual(r.list[11].sni, 'telerad.demo');
assert.strictEqual(r.stats.handshakes, 3);
assert.strictEqual(r.stats.unanswered, 0);
const codes = r.stats.alerts.map((a) => a.code);
for (const c of ['clear', 'retrans', 'nxdomain', 'scan']) assert.ok(codes.includes(c), 'alerte ' + c);
assert.strictEqual(r.stats.alerts.find((a) => a.code === 'clear').value, 'radiologue.demo:demo1234');
assert.strictEqual(r.stats.alerts.find((a) => a.code === 'scan').n, 16);

// 4. Une trame altérée est détectée (somme de contrôle TCP incorrecte)
const buf = E.toPcap(E.build());
new Uint8Array(buf)[24 + 16 * 9 + r.list.slice(0, 8).reduce((a, p) => a + p.caplen, 0) + 60] ^= 0xff;   // un octet de la trame 9
const r2 = P.load(buf);
assert.ok(r2.list[8].flags.badCsum, 'trame altérée détectée');

// 5. Filtres d'affichage
const f = (s) => r.list.filter(P.compileFilter(s)).length;
assert.strictEqual(f('arp'), 2);
assert.strictEqual(f('dns'), 4);
assert.strictEqual(f('tcp.port == 443 and not tls'), 6);
assert.strictEqual(f('ip.src == 192.168.11.10 and tcp'), 19);
assert.strictEqual(f('(http or ftp) and ip.dst == 192.168.101.10'), 4);
assert.throws(() => P.compileFilter('tcp.port =='));
assert.throws(() => P.compileFilter('champ.inconnu == 3'));

console.log('OK : tous les tests passent');
