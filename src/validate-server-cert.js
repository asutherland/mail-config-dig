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
        console.log('  - in verify');
        resolveAndCleanup(certHelper.certCheck(opts.host, arguments));
        return true;
      },
      connected: function(connection) {
        console.log('  - in connected');
      },
      tlsDataReady: function(connection) {
        console.log('  - in tlsDataReady');
        // encrypted data is ready to be sent to the server
        var data = connection.tlsData.getBytes();
        socket.write(data, 'binary'); // encoding should be 'binary'
      },
      dataReady: function(connection) {
        console.log('  - in dataReady');
      },
      closed: function() {
        console.log('  - closed?!');
        reject('closed');
      },
      error: function(connection, error) {
        console.log('error?!');
        reject(error);
      }
    });

    socket.on('connect', function() {
      console.log('  - socket connected');
      client.handshake();
    });
    socket.on('data', function(data) {
      console.log('  - passing data through');
      client.process(data.toString('binary')); // encoding should be 'binary'
    });
    socket.on('end', function() {
      console.log('  - socket ended');
    });

    console.log('- connecting to', opts.host, 'port', opts.port);
    socket.connect(opts.port, opts.host);
  });
};
