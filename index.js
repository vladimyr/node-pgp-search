'use strict';

global.URL = global.URL = require('url').URL;

const { format, promisify } = require('util');
const request = promisify(require('request'));
const url = require('native-url');

const reHex = /^(0x)?[a-fA-F0-9]+$/;

/**
 * Pool of key servers that accept the self signed CA certificate
 * and that are up to date with the latest 1.1.5 version.
 */
const keyServers = [
  'pgp.key-server.io',
  'keyserver.ubuntu.com'
];

const randomKeyServer = () => {
  const index = Math.floor(Math.random() * keyServers.length);
  return keyServers[index];
};

module.exports = {
  keyServers,
  index,
  get
};

/**
 * Get list of keys for given search query
 * @param {String} search email, key id or fingerprint
 * @param {Object} [options]
 * @param {Boolean} [options.exactMatch=false] force exact match
 * @returns {Promise<Array<Key>>} retrived keys
 *
 * @example
 * const keys = await pgpsearch.index('xdamman@gmail.com');
 * //=>
 * [{
 *   fingerprint: '44A7D05FF1F6D0B80F7915A614261B13FD430CDC',
 *   bits: 4096,
 *   date: '2014-02-25T22:01:07.000Z',
 *   flags: null
 * }]
 */
async function index (search, { exactMatch = false } = {}) {
  search = processSearch(search);
  const url = buildUrl({ op: 'index', search });
  if (exactMatch) {
    url.searchParams.set('exact', 'on');
  }
  const resp = await request(url.href);
  if (resp.statusCode !== 200) {
    throw new Error('Not Found');
  }
  const lines = resp.body.split(/\r?\n/);
  return lines.reduce((acc, line) => {
    const columns = line.split(':');
    if (columns[0] !== 'pub') {
      return acc;
    }
    const fingerprint = columns[1];
    if (fingerprint.length !== 40) {
      console.error('Invalid PGP fingerprint:', fingerprint);
      return acc;
    }
    const bits = parseInt(columns[3], 10);
    const date = new Date(parseInt(columns[4], 10) * 1000 /* ms */);
    const flags = columns[6] || null;
    acc.push({ fingerprint, bits, date, flags });
    return acc;
  }, []);
}

/**
 * Get the PGP key for given search query
 * @param {String} search email, key id, or fingerprint
 * @returns {Promise<String>} armor
 *
 * @example
 * const pgp = await pgpsearch.get('0x44A7D05FF1F6D0B80F7915A614261B13FD430CDC');
 * //=>
 * `-----BEGIN PGP PUBLIC KEY BLOCK-----
 * Version: SKS 1.1.6+
 * Comment: Hostname: pgp.key-server.io
 *
 * mQINBFMNEqMBEACYhMtXUVtmTMwz77Gf5/FUYSnFW22MBAo0ExwCUAi6xXIJHtVcVml//44D
 * 3mbAeaUPejiaS7DBXlomlxroCq2a1+qfqI0lVX+KNzUhDYjjcUsT7N6cMNLxBkaA5YOkrkZS…`
 */
async function get (search) {
  search = processSearch(search);
  const url = buildUrl({ op: 'get', search });
  const resp = await request(url.href);
  if (resp.statusCode !== 200) {
    throw new Error('Not Found');
  }
  return resp.body;
}

function processSearch (search) {
  if (search.includes('@')) {
    return search;
  }
  if (reHex.test(search)) {
    return format('0x%s', search.replace(/^0x/, '').toUpperCase());
  }
}

function buildUrl ({ host = randomKeyServer(), op, search }) {
  const query = {
    search,
    op,
    fingerprint: 'on',
    options: 'mr'
  };
  return new URL(url.format({
    protocol: 'https:',
    host,
    pathname: '/pks/lookup',
    query
  }));
}

/**
* @typedef {Object} Key
* @property {String} fingerprint fingerprint
* @property {Number} bits key size
* @property {Date} date creation date
* @property {String|null} flags optional key flags
*/
