'use strict';

const dns = require('dns');
const tld = require('tld');

/**
 * Run MX lookups, find the effective tld+1 domain, uniqueify over those.
 */
module.exports = function mxLookup(domain) {
  return new Promise(function(resolve, reject) {
    dns.resolveMx(domain, function(err, results) {
      if (err) {
        reject(err);
        return;
      }
      var domains = results.map(function(info) {
        return info.exchange;
      });
      var uniqueRoots = [];
      domains.forEach(function(domain) {
        var effectiveRoot = tld.registered(domain);
        if (uniqueRoots.indexOf(effectiveRoot) === -1) {
          uniqueRoots.push(effectiveRoot);
        }
      });
      resolve({
        domains: domains,
        uniqueRoots: uniqueRoots
      });
    });
  });
};
