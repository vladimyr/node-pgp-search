var fs = require('fs')
  , request = require('request');

/*
 * Pool of key servers that accept the self signed CA certificate
 * and that are up to date with the latest 1.1.5 version
 */
var sks_servers = [
  "pgp.key-server.io"
  , "keyserver.ubuntu.com"
  , "key.ip6.li"
];

var getSKSserver = function() {
  var index = Math.floor(Math.random()*sks_servers.length);
  return "https://"+sks_servers[index];
};

var requestOptions = {};

module.exports = {

  keyServers: sks_servers,

  index: function(email, fn) {
    var selectedHost = getSKSserver()
    requestOptions.url = selectedHost + "/pks/lookup?search="+encodeURIComponent(email)+"&op=index&fingerprint=on&options=mr";
    request(requestOptions, function(err, res, body) {
      if(err) console.error(err, selectedHost);
      if(err) return fn(new Error(err.message + " - Host:" + selectedHost));
      if(res.statusCode != 200) return fn(new Error("Not Found - Host:" + selectedHost));


      var lines = body.split('\n');
      var keys = [];
      for(var i=0;i<lines.length;i++) {
        var l = lines[i];
        if(l.substr(0,3) == 'pub') {
          var cols = l.split(':');
          if(cols[1].length == 40)
	    var f = null;
	    if cols.length == 7:
	      f = cols[6];
            keys.push({fingerprint: cols[1], bits: cols[3], date: new Date(parseInt(cols[4]+'000',10)), flags: f });
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

