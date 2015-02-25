var fs = require('fs')
  , request = require('request');

/*
 * Pool of key servers that accept the self signed CA certificate
 * and that are up to date with the latest 1.1.5 version
 */
var sks_servers = [
    "a.keyserver.pki.scientia.net"
  , "ams.sks.heypete.com"
  , "keys.alderwick.co.uk"
  , "keys.digitalis.org"
  , "keys2.alderwick.co.uk"
  , "keys2.kfwebs.net"
  , "keyserver.br.nucli.net"
  , "keyserver.codinginfinity.com"
  , "keyserver.nucli.net"
  , "keyserver.secretresearchfacility.com"
  , "keyserver.secure-u.de"
  , "keyserver.stack.nl"
  , "keyserver.ut.mephi.ru"
  , "klucze.achjoj.info"
  , "pgp.archreactor.org"
  , "pgpkeys.co.uk"
  , "pgpkeys.eu"
];

var getSKSserver = function() {
  var index = Math.floor(Math.random()*sks_servers.length);
  return "https://"+sks_servers[index];
};

var requestOptions = {
  agentOptions: {
    ca: fs.readFileSync(__dirname+'/sks-keyservers.netCA.pem')
  }
};

module.exports = {

  index: function(email, fn) {

    requestOptions.url = getSKSserver() + "/pks/lookup?search="+encodeURIComponent(email)+"&op=index&fingerprint=on&options=mr";
    request(requestOptions, function(err, res, body) {
      if(err) console.error(err);
      if(err) return fn(err);
      if(res.statusCode != 200) return fn(new Error("Not Found"));


      var lines = body.split('\n');
      var keys = [];
      for(var i=0;i<lines.length;i++) {
        var l = lines[i];
        if(l.substr(0,3) == 'pub') {
          var cols = l.split(':');
          if(cols[1].length == 40)
            keys.push({fingerprint: cols[1], bits: cols[3], date: new Date(parseInt(cols[4]+'000',10)) });
          else {
            console.error("Invalid PGP fingerprint: ", cols[1]);
          }
        }
      }
      fn(err, keys);
    });

  },

  get: function(fingerprint, fn) {
    requestOptions.url = getSKSserver() + "/pks/lookup?search=0x"+fingerprint+"&op=get&fingerprint=on&options=mr";
    request(requestOptions, function(err, res, body) {
      if(err) return fn(err);
      if(res.statusCode != 200) return fn(new Error("Not Found"));
      return fn(null, body);
    });
  }

};

