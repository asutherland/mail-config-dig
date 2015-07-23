'use strict';

/**
 * Automate mail server investigations.
 *
 * Things marked with NOTYET below are speculative.
 *
 * For a mail domain (ex: gmail.com), we can:
 * - perform MX lookups (NOTYET)
 * - perform domain guessing (NOTYET)
 *
 * For a mail server (IMAP/POP3/SMTP), we can:
 * - validate certificates (NOTYET)
 * - find maybe better and suspicious domain names given an otherwise valid
 *   certificate.  (A maybe better domain name is under the same TLD+1 or
 *   the TLD+1 of where the MX ends up.  A domain is suspicious if it points
 *   elsewhere.)  (NOTYET)
 */

const program = require('commander');
const validateServerCert = require('./validate-server-cert');
const mxLookup = require('./mx-lookup');

function parsePortOrService(portOrService) {
  // Yes, we could depend on /etc/services and it being correct.  And people
  // knowing the likely accepted names...
  switch (portOrService) {
    case 'simap':
    case 'imaps':
      return 993;
    case 'imap':
      return 143;
    case 'pops':
    case 'pop3s':
    case 'spop':
      return 995;
    case 'pop':
    case 'pop3':
      return 110;
    case 'ssmtp':
    case 'smtps':
      return 465;
    case 'smtp':
    case 'submission':
      return 587;
    case 'lowsmtp':
      return 25;
    default:
      var port = parseInt(portOrService, 10);
      if (isNaN(port)) {
        throw new Error('bad port: ' + portOrService);
      }
      return port;
  }
}

program
  .command('mx <domain>')
  .action(function(domain) {
    mxLookup(domain).then(function(results) {
      console.log('servicing domain:', results.uniqueRoots);
      console.log('full domains:', results.domains);
    });
  });

program
  .command('validate <mailhost> <port-or-service>')
  .action(function(host, portStr) {
    validateServerCert({
      host: host,
      port: parsePortOrService(portStr)
    }).then(function(result) {
      console.log('result:', result);
    });
  });

program.parse(process.argv);
