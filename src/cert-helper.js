// Copyright (c) 2014 Whiteout Networks

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
'use strict';

/*
 * sourcing: This is from whiteout-io's tcp-socket wrapper that uses node-forge.
 * I've chopped the contents of the file down to just the logic we need, but
 * that's why it's got that copyright up there.  See the original code at:
 * https://github.com/whiteout-io/tcp-socket/blob/master/src/tcp-socket-tls.js
 */

/**
 * The only intent for the logic in this file is for investigation of mail
 * server configurations where the final determination is made by humans.  This
 * logic should not be used for actual TLS purposes (even if that's where it
 * originally came from) or otherwise as an alternative for the decisions made
 * by a proper TLS stack.  It's assumed Gecko's Necko/NSS layers will be used
 * for all actual connections in the end, so as long as the humans involved in
 * the auditing process are suspicious about the domains in play, we leave it
 * to NSS/Necko for proper strict enforcement of certificate validity assuming
 * the humans made the right DNS calls.
 **/

const forge = require('node-forge');

module.exports = {
  /**
   * Helper functions to take a forge "verify" function's received arguments,
   * the host name being used to connect, and distill the results to one
   * of the following:
   * - invalid: There is no set of domains for which this certificate is valid
   *   because it's self-signed or the date is wrong or the CA is invalid, etc.
   * - valid : The certificate is valid for the host name being used.
   * - invalid-for-this-domain: The certificate is not valid for this domain,
   *   but there are domains for which it is valid.
   *
   * The returned object will contain the following fields:
   * - status: invalid/valid/invalid-for-this-domain
   * - extendedStatus: A maybe-useful elaboration on the error.
   * - validForDomains: A list of domains the result is valid for.
   *
   */
  certCheck: function(host, verifyArgs) {
    var priorValid = verifyArgs[1];
    var certs = verifyArgs[3];

    if (priorValid !== true || !(certs && certs[0])) {
      return {
        status: 'invalid',
        extendedStatus: 'no-valid-certs',
      };
    }
    var cert = certs[0];

    var cn, subjectAltName, entries, self = this;

    subjectAltName = cert.getExtension({
        name: 'subjectAltName'
    });

    cn = cert.subject.getField('CN');

    // If subjectAltName is present then it must be used and Common Name must be
    // discarded http://tools.ietf.org/html/rfc2818#section-3.1 So we check
    // subjectAltName first and if it does not exist then revert back to
    // Common Name
    if (subjectAltName &&
        subjectAltName.altNames &&
        subjectAltName.altNames.length) {
      entries = subjectAltName.altNames.map(function(entry) {
        return entry.value;
      });
    } else if (cn && cn.value) {
      entries = [cn.value];
    } else {
      return {
        status: 'invalid',
        extendedStatus: 'no-valid-certs'
      };
    }

    // find matches for hostname
    var validDomains = entries.filter(function(sanEntry) {
        return self.compareServername(host, sanEntry);
    });

    return {
      status: validDomains.length ? 'valid' : 'invalid-for-this-domain',
      extendedStatus: 'meh',
      validForDomains: entries
    };
  },

  /**
   * Compares servername with a subjectAltName entry. Returns true if these values match.
   *
   * Wildcard usage in certificate hostnames is very limited, the only valid usage
   * form is "*.domain" and not "*sub.domain" or "sub.*.domain" so we only have to check
   * if the entry starts with "*." when comparing against a wildcard hostname. If "*" is used
   * in invalid places, then treat it as a string and not as a wildcard.
   *
   * @param {String} servername Hostname to check
   * @param {String} sanEntry subjectAltName entry to check against
   * @returns {Boolean} Returns true if hostname matches entry from SAN
   */
  compareServername: function(servername, sanEntry) {
    // normalize input values
    servername = (servername || '').toString().toLowerCase();
    sanEntry = (sanEntry || '').toString().toLowerCase();

    // if the entry name does not include a wildcard, then expect exact match
    if (sanEntry.substr(0, 2) !== '*.') {
      return sanEntry === servername;
    }

    // otherwise ignore the first subdomain
    return servername.split('.').slice(1).join('.') === sanEntry.substr(2);
  },
};
