import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { parseCsv, parseXlsx } from '../src/sheet';

test('CSV: quotes, embedded commas and newlines, semicolons, BOM, blank lines', () => {
  assert.deepEqual(parseCsv('﻿id,title\r\nA.1,"Policy, approved"\r\n\r\nA.2,"Say ""hi""\nsecond line"\n'), [['id', 'title'], ['A.1', 'Policy, approved'], ['A.2', 'Say "hi"\nsecond line']]);
  assert.deepEqual(parseCsv('id;title\nA.1;x,y'), [['id', 'title'], ['A.1', 'x,y']]);
});

test('XLSX written by Excel tooling: every tab in order, shared strings, numbers, escapes, gaps', async () => {
  const sheets = await parseXlsx(readFileSync(join(import.meta.dirname, 'fixtures', 'framework-sample.xlsx')));
  assert.deepEqual(sheets.map((x) => x.name), ['Notes', 'Controls']);
  assert.deepEqual(sheets[1]!.rows, [
    ['Control ID', 'Title', 'Description'],
    ['A.5.1', 'Policies for information security', 'Policy defined, approved & published'],
    ['A.5.2', 'Roles', 'Say "hi" <b> ü'],
    ['A.5.3', '42'],
  ]);
  await assert.rejects(parseXlsx(new TextEncoder().encode('not a zip')), /not an XLSX/);
});
