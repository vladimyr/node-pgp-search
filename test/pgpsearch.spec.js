'use strict';

global.URL = global.URL = require('url').URL;

const { expect } = require('chai');
const openpgp = require('openpgp');
const pgpsearch = require('../');
const { promisify } = require('util');
const request = promisify(require('request'));
const url = require('native-url');

pgpsearch.get = promisify(pgpsearch.get);
pgpsearch.index = promisify(pgpsearch.index);

const email = 'xdamman@gmail.com';
const fingerprint = '44A7D05FF1F6D0B80F7915A614261B13FD430CDC';

describe('pgp', function () {
  it('All the servers should work', () => {
    const query = {
      search: email,
      op: 'index',
      fingerprint: 'on',
      options: 'mr'
    };
    return Promise.all(pgpsearch.keyServers.map(async server => {
      const lookupUrl = url.format({
        protocol: 'https:',
        host: server,
        pathname: '/pks/lookup',
        query
      });
      const resp = await request(lookupUrl);
      if (resp.statusCode !== 200) {
        throw new Error(`HTTPError: Response code ${resp.statusCode} (${resp.statusMessage})`);
      }
    }));
  });

  it('Finds the public PGP key for an email address', async () => {
    const keys = await pgpsearch.index(email);
    expect(keys.length).to.equal(1);
    expect(keys[0].fingerprint).to.equal(fingerprint);
  });

  it("Returns an error if can't find a PGP key", async () => {
    try {
      await pgpsearch.index('notfound' + email);
    } catch (err) {
      expect(err).to.exist;
    }
  });

  it('Returns multiple keys', async () => {
    const email = 'glenn.greenwald@theintercept.com';
    const keys = await pgpsearch.index(email);
    expect(keys.length > 1).to.be.true;
  });

  it('Gets the PGP public key given a fingerprint', async () => {
    const pgp = await pgpsearch.get(fingerprint);
    const publicKey = openpgp.key.readArmored(pgp);
    const publicKey_fingerprint = publicKey.keys[0].primaryKey.getFingerprint().toUpperCase();
    expect(publicKey_fingerprint).to.equal(fingerprint);
  });

  it("Returns an error if it can't find a PGP key for a given fingerprint", async () => {
    try {
      await pgpsearch.get(fingerprint.replace(/[0-9]/g, '0'));
    } catch (err) {
      expect(err).to.exist;
    }
  });
});
