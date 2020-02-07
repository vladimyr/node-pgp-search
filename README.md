node-pgp-search
===============

Search for a PGP key by email address using SKS Key Servers

## Install

    npm install node-pgp-search

## Usage

    var pgpsearch = require('node-pgp-search');
    
### Get the list of keys for a given email address

    pgpsearch.index(email, function(err, keys) {
      // keys is an array of object { fingerprint: "", bits: 4096, date: Date }
    });

### Get the PGP key for a given fingerprint

    pgpsearch.get("0x44A7D05FF1F6D0B80F7915A614261B13FD430CDC", function(err, pgp) {
      // PGP is the public key for the given fingerprint
    });


## Tests

    npm run test
