import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { signAws } from '../src/sigv4';

// AWS's published SigV4 example (IAM ListUsers, 2015-08-30T12:36:00Z) from the AWS General Reference,
// "Examples of the complete Signature Version 4 signing process".
test('SigV4 matches the AWS documentation example', () => {
  const h = signAws({
    method: 'GET',
    url: new URL('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08'),
    region: 'us-east-1',
    service: 'iam',
    headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    credentials: { access_key_id: 'AKIDEXAMPLE', secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' },
    now: new Date('2015-08-30T12:36:00Z'),
  });
  assert.equal(
    h.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
  );
});
