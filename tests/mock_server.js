const https = require('https');
const fs = require('fs');

const REQUIRED_FILES = [
  '/app/config/server.key',
  '/app/config/server.crt',
  '/app/config/ca.crt'
];

function waitForCertsAndStart() {
  for (const file of REQUIRED_FILES) {
    if (!fs.existsSync(file)) {
      console.log(`Waiting for certificate file: ${file}...`);
      setTimeout(waitForCertsAndStart, 1000);
      return;
    }
  }

  console.log('All certificates found. Starting mock HTTPS servers...');

  const certOptions = {
    key: fs.readFileSync('/app/config/server.key'),
    cert: fs.readFileSync('/app/config/server.crt'),
    ca: fs.readFileSync('/app/config/ca.crt'),
    requestCert: true,
    rejectUnauthorized: false
  };

  // 1. Port 1234: HTTPS with mTLS support
  https.createServer(certOptions, (req, res) => {
    const isAuthorized = req.client.authorized || false;
    const peerCert = req.socket.getPeerCertificate();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      protocol: 'https',
      mtls: isAuthorized,
      clientSubject: peerCert ? peerCert.subject : null,
      headers: req.headers
    }));
  }).listen(1234, '0.0.0.0', () => {
    console.log('Mock HTTPS server with mTLS active on port 1234');
  });

  // 2. Port 1235: Standard HTTPS (no client certificate required)
  https.createServer({
    key: fs.readFileSync('/app/config/server.key'),
    cert: fs.readFileSync('/app/config/server.crt')
  }, (req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      protocol: 'https',
      tls: true,
      headers: req.headers
    }));
  }).listen(1235, '0.0.0.0', () => {
    console.log('Mock HTTPS server active on port 1235');
  });
}

waitForCertsAndStart();
