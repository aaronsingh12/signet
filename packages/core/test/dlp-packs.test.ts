import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { PACKS, bsnOk, codiceFiscaleOk, cpfOk, dniOk, enabledPacks, ipv4Ok, luhnOk, myNumberOk, nirOk, nricOk, tfnOk, verhoeffOk } from '../src/dlp-packs';
import { scan } from '../src/dlp';
import { ninoOk as ninoOkSample } from '../src/dlp-packs';

// Country packs (BP 5.3): each identifier is found only with a valid check digit (and, for numbers that
// look like any other number, only next to its keyword).

// The one final character that makes a number valid, found by trying every candidate.
const complete = (prefix: string, ok: (s: string) => boolean, alphabet = '0123456789') => {
  const hits = [...alphabet].map((c) => prefix + c).filter(ok);
  assert.equal(hits.length, 1, `exactly one check character for ${prefix}`);
  return hits[0]!;
};

test('check digits: known valid numbers pass, one changed digit fails', () => {
  assert.ok(cpfOk('529.982.247-25') && !cpfOk('529.982.247-26') && !cpfOk('111.111.111-11'));
  assert.ok(nricOk('S1234567D') && !nricOk('S1234567A'));
  assert.ok(!ninoOkSample('QQ123456C'), 'QQ is a documentation-only prefix');
  assert.ok(tfnOk('123 456 782') && !tfnOk('123 456 781'));
  assert.ok(bsnOk('111222333') && !bsnOk('111222334'));
  assert.ok(dniOk('12345678Z') && !dniOk('12345678A') && dniOk('X1234567L'));
  assert.ok(codiceFiscaleOk('RSSMRA85T10A562S') && !codiceFiscaleOk('RSSMRA85T10A562T'));
  assert.ok(ipv4Ok('192.168.1.20') && !ipv4Ok('300.1.1.1') && !ipv4Ok('01.2.3.4'));
  const aadhaar = complete('23412341234', verhoeffOk);
  assert.ok(!verhoeffOk(aadhaar.slice(0, 11) + ((Number(aadhaar[11]) + 1) % 10)));
  const nirFull = ['1850578006084' + String(97 - Number(1850578006084n % 97n)).padStart(2, '0')][0]!;
  assert.ok(nirOk(nirFull));
  assert.ok(myNumberOk(complete('12345678901', myNumberOk)));
  assert.ok(luhnOk(complete('78412341234567', luhnOk)));
});

test('scan finds national IDs, with their keyword where one is required', () => {
  const tags = (text: string) => scan(text).map((f) => f.recogniser);
  assert.deepEqual(tags('SSN 123-45-6789 on file'), ['us_ssn']);
  assert.deepEqual(tags('NI number AB 12 34 56 C'), ['uk_nino']);
  assert.deepEqual(tags(`Aadhaar ${complete('23412341234', verhoeffOk)} and PAN ABCPE1234F`), ['in_aadhaar', 'in_pan']);
  assert.deepEqual(tags('NRIC S1234567D'), ['sg_nric']);
  assert.deepEqual(tags('CPF 529.982.247-25'), ['br_cpf']);
  assert.deepEqual(tags('codice fiscale RSSMRA85T10A562S, DNI 12345678Z'), ['it_codice_fiscale', 'es_dni']);
  assert.deepEqual(tags(`Emirates ID ${complete('78412341234567', luhnOk).replace(/^(\d{3})(\d{4})(\d{7})(\d)$/, '$1-$2-$3-$4')}`), ['ae_emirates_id']);
  // Needs a keyword: the same digits alone are left alone.
  assert.deepEqual(tags('my TFN is 123 456 782'), ['au_tfn']);
  assert.ok(!tags('order 123456782 shipped').includes('au_tfn'), 'no keyword, no tax file number');
  assert.deepEqual(tags('BSN 111222333'), ['nl_bsn']);
  assert.deepEqual(tags('passport number X1234567 issued 2020'), ['passport']);
  assert.deepEqual(tags('date of birth 14/03/1988'), ['date_of_birth']);
  assert.deepEqual(tags('the meeting is on 14/03/2026'), []);
  assert.deepEqual(tags('SWIFT DEUTDEFF500'), ['swift_bic']);
  assert.deepEqual(tags('login from 203.0.113.9'), ['ipv4']);
  // Cards and secrets still win over everything else.
  assert.deepEqual(tags('card 4111 1111 1111 1111'), ['payment_card']);
});

test('pack settings: default leaves the restricted health pack off; unknown packs are refused', () => {
  assert.ok(!enabledPacks(undefined).includes('health'));
  assert.deepEqual(enabledPacks('us,uk'), ['us', 'uk']);
  assert.deepEqual(enabledPacks('none'), []);
  assert.deepEqual(enabledPacks('all'), Object.keys(PACKS));
  assert.throws(() => enabledPacks('us,mars'), /unknown pack/);
  assert.deepEqual(scan('diagnosed with diabetes').map((f) => f.tag), [], 'health terms are not flagged by default');
});
