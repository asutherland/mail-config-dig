'use strict';

const dns = require('dns');
const tld = require('tld');


function resolveCnames(domain) {
  return new Promise(function(resolve, reject) {
    dns.resolveCname(domain, function(err, cnames) {
      if (err) {
        if (err.code === 'ENODATA') {
          cnames = [];
        } else {
          reject(err);
          return;
        }
      }
      resolve(cnames);
    });
  });
}

function resolveIps(domain) {
  return new Promise(function(resolve, reject) {
    dns.resolve(domain, function(err, ips) {
      if (err) {
        reject(err);
        return;
      }
      resolve(ips);
    });
  });
}

function reverseIp(ip) {
  return new Promise(function(resolve, reject) {
    dns.reverse(ip, function(err, hostnames) {
      if (err) {
        reject(err);
        return;
      }
      resolve(hostnames);
    });
  });
}

function uniqueifyList(list) {
  var uniqued = [];
  list.forEach(function(x) {
    if (uniqued.indexOf(x) === -1) {
      uniqued.push(x);
    }
  });
  return uniqued;
}

function reverseIpsAndUniqueify(ips) {
  var reversePromises = [];
  ips.forEach(function(ip) {
    reversePromises.push(reverseIp(ip));
  });
  return Promise.all(reversePromises).then(function(hostnameLists) {
    var allHostnames = [].concat.apply([], hostnameLists);
    return uniqueifyList(allHostnames);
  });
}

/**
 * Resolve the domain to an IP and then reverse it, also getting any (first
 * level) cname(s).
 */
module.exports = function reverseLookup(domain) {
  var results = {};

  // -- Get the cnames and ips
  return Promise.all([
    resolveCnames(domain),
    resolveIps(domain)
  ]).then(function(cnameAndIps) {
    var cnames = cnameAndIps[0];
    var ips = cnameAndIps[1];
    results.cnames = cnames;
    results.ips = ips;
    return reverseIpsAndUniqueify(ips);
  }).then(function(reversedHostnames) {
    results.reversed = reversedHostnames;
    return results;
  });
};
