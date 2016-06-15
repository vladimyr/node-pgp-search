var openpgp = require('openpgp');
var expect = require('chai').expect;
var pgpsearch = require('../');
var request = require('request');

var email = "xdamman@gmail.com";
var fingerprint = "44A7D05FF1F6D0B80F7915A614261B13FD430CDC";


describe("pgp", function() {

  it("All the servers should work", function(done) {
    this.timeout(10*1000);
    var n = pgpsearch.keyServers.length
    var complete = 0

    function response(err, res, body) {
      if (err) {
        done(err)
      }
      if (res.statusCode !== 200) {
        done(new Error("Error: Status: " + res.statusCode))
      }
      complete = complete + 1
      if (complete === n) {
        done()
      }
    }

    for (var i=0; i < pgpsearch.keyServers.length; i++) {
      var requestOptions = {};
      requestOptions.url = "https://" +pgpsearch.keyServers[i] + "/pks/lookup?search="+encodeURIComponent(email)+"&op=index&fingerprint=on&options=mr";
      request(requestOptions, response)
    }

  });


  it("Finds the public PGP key for an email address", function(done) {

    this.timeout(3500);

    pgpsearch.index(email, function(e, keys) {
      expect(e).to.not.exist;
      expect(keys.length).to.equal(1);
      expect(keys[0].fingerprint).to.equal(fingerprint);
      done();
    });

  });

  it("Returns an error if can't find a PGP key", function(done) {
    this.timeout(3500);
    pgpsearch.index('notfound'+email, function(e, res) {
      expect(e).to.exist;
      done();
    });
  });
  
  it("Returns multiple keys", function(done) {
    this.timeout(3500);
    var email = "glenn.greenwald@theintercept.com";
    pgpsearch.index(email, function(e, keys) {
      expect(e).to.not.exist;
      expect(keys.length > 1).to.be.true;
      done();
    });
  });

  it("Gets the PGP public key given a fingerprint", function(done) {
    this.timeout(6000);
    pgpsearch.get(fingerprint, function(e, pgp) {
      expect(e).to.not.exist;

      var publicKey = openpgp.key.readArmored(pgp);
      var publicKey_fingerprint = publicKey.keys[0].primaryKey.getFingerprint().toUpperCase();
      expect(publicKey_fingerprint).to.equal(fingerprint);

      done();
    });
  });

  it("Returns an error if it can't find a PGP key for a given fingerprint", function(done) {
    this.timeout(3500);
    pgpsearch.get(fingerprint.replace(/[0-9]/g,'0'), function(e, pgp) {
      expect(e).to.exist;
      done();
    });
  });

});

