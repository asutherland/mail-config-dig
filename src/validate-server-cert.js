'use strict';

const net = require('net');
const forge = require('node-forge');
const certHelper = require('./cert-helper');

module.exports = function validateServerCert(opts) {
  return new Promise(function(resolve, reject) {
    var socket = new net.Socket();

    var cleanup = function() {
      if (socket) {
        socket.close();
        socket = null;
      }
    };

    var resolveAndCleanup = function(result) {
      resolve(result);
      cleanup();
    };

    var client = forge.tls.createConnection({
      server: false,
      verify: function(connection, verified, depth, certs) {
        resolveAndCleanup(certHelper.certCheck(opts.host, arguments));
        return true;
      },
      connected: function(connection) {
      },
      tlsDataReady: function(connection) {
        // encrypted data is ready to be sent to the server
        var data = connection.tlsData.getBytes();
        socket.write(data, 'binary'); // encoding should be 'binary'
      },
      dataReady: function(connection) {
      },
      closed: function() {
        reject('closed');
      },
      error: function(connection, error) {
        reject(error);
      }
    });

    socket.on('connect', function() {
      client.handshake();
    });
    socket.on('data', function(data) {
      client.process(data.toString('binary')); // encoding should be 'binary'
    });
    socket.on('end', function() {
    });

    socket.connect(opts.port, opts.host);
  });
};
