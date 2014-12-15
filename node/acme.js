var async  = require("async");
var http   = require("http");
var url    = require("url");
var tls    = require("tls");
var crypto = require("./crypto-util");
var util   = require("./acme-util");

/***** Constants *****/
const ENABLE_DEBUG          =  true;
const CLIENT_KEY_SIZE       =  512;
const DEFAULT_POLL_INTERVAL =  1000; // msec
const MIN_POLL_INTERVAL     =  2000; // msec
const MAX_POLL_INTERVAL     = 10000; // msec
const MAX_POLL              =  1000;
const VALIDATION_METHOD     = "simpleHttps";
const DVSNI_SUFFIX          = ".acme.invalid";

// By default, assume we're on heroku
// Local usage requires:
// * Different ports
// * Connecting to localhost in *Validation below
var ENABLE_LOCAL_USAGE = false;
var VALIDATION_DEFAULT_PORT = 5001;
var VALIDATION_CLIENT_PORT =  80;
var VALIDATION_SERVER_PORT =  process.env.PORT;

function enableLocalUsage() {
  ENABLE_LOCAL_USAGE = true;
  VALIDATION_CLIENT_PORT = VALIDATION_DEFAULT_PORT;
  VALIDATION_SERVER_PORT = VALIDATION_DEFAULT_PORT;
}


function DEBUG(message) {
  if (ENABLE_DEBUG) {
    console.log(message);
  }
}

/***** Default TLS certificate *****/

// The TLS server used for DVSNI requires a default key
// and certificate.  This is a valid key and cert, but it
// should never be accepted.

var DEFAULT_KEY =
  "-----BEGIN RSA PRIVATE KEY-----\n" +
  "MIIBOwIBAAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLH\n" +
  "kcBeriMhC37DUygRigkEea5RSQkJcE521s8CAwEAAQJAcfjsu6iqNZdYLFpx/YOP\n" +
  "TIkKrgzzwqa+3KoYO8V3cVlNEZbzSFn0CAnznLPYzAY7yibDAVYWLVgJsdldOvtQ\n" +
  "UQIhAMH/JrN5znZigVnqxFrHJGbNjBTnir9CG1YYZsXWrIjJAiEAulEKSqpnuv9C\n" +
  "5btfRZ2E0oVal6+XzOajNagMqPJhRtcCIQCui7nwhcnj7mFf28Frw/3WmV5OeL33\n" +
  "s60Q28esfaijMQIgOjwCP3wrl+MZAb0i9htZ3IMZ4bdcdwrPkIHKEzRO+1kCIQC/\n" +
  "jUlCS7ny/4g4tY5dngWhQk3NUJasFzNuzTSx4ZGYWw==\n" +
  "-----END RSA PRIVATE KEY-----\n";

var DEFAULT_CERT =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBWDCCAQKgAwIBAgIBATANBgkqhkiG9w0BAQUFADAcMRowGAYDVQQDExFhbm9u\n" +
  "eW1vdXMuaW52YWxpZDAeFw0xNDA5MTMxOTU1MjRaFw0xNTA5MTMxOTU1MjRaMBwx\n" +
  "GjAYBgNVBAMTEWFub255bW91cy5pbnZhbGlkMFwwDQYJKoZIhvcNAQEBBQADSwAw\n" +
  "SAJBAI0wy6Yxr8oK4IVCt7Ma+0rFDUJqA0xeDxrJ6xg8wVfaQydnNXLHkcBeriMh\n" +
  "C37DUygRigkEea5RSQkJcE521s8CAwEAAaMvMC0wCQYDVR0TBAIwADALBgNVHQ8E\n" +
  "BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQEFBQADQQBpHaM7\n" +
  "mwRj19nt7sGb/trlxu5Ra0Ic4RGLI/VOZGWVV6hb2G559J2WdrdMS98U3L95lOoX\n" +
  "2fhD1yUCrh3aNtZP\n" +
  "-----END CERTIFICATE-----\n";

/***** Validation Methods *****/

function SimpleHttpsResponse(challenge) {
  return {
    type: "simpleHttps",
    token: challenge.token,
    path: crypto.newToken()
  };
}

function SimpleHttpsServer(domain, challenge, response) {
  console.log("---> Creating SimpleHttpsServer on port " + VALIDATION_SERVER_PORT);
  console.log("     Looking for path "+ response.path);
  return http.createServer(function(req, resp) {
    console.log("---> Got request to ACME validation endpoint");
    console.log("~~~> url = " + req.url)
    console.log("~~~> my  = /.well-known/acme-challenge/" + response.path);
    if (req.url == "/.well-known/acme-challenge/" + response.path) {
      resp.writeHead(200, "OK", { "content-type": "text/plain" });
      resp.write(challenge.token);
    } else {
      resp.writeHead(404, "Not Found");
    }
    resp.end();
  });
}

function DvsniResponse(challenge) {
  return {
    type: "dvsni",
    s: crypto.randomString(32)
  }
}

function DvsniServer(domain, challenge, response) {
  // Do all the crypto computations we need
  var nonceName = challenge.nonce + DVSNI_SUFFIX;
  var RS = Buffer.concat([util.b64dec(challenge.r), util.b64dec(response.s)]);
  var zName = crypto.sha256(RS).toString("hex") + DVSNI_SUFFIX;

  // Generate a key pair and certificate
  var keyPair = crypto.generateKeyPair(CLIENT_KEY_SIZE);
  var cert = crypto.generateDvsniCertificate(keyPair, nonceName, zName);
  var context = crypto.createContext(keyPair, cert);

  return tls.createServer({
    key: DEFAULT_KEY,
    cert: DEFAULT_CERT,
    SNICallback: function(serverName) {
      if (serverName == nonceName) {
        return context;
      }
    }
  });
}

/***** Client helper methods *****/

// Slightly simplified HTTP request method.
// * If body != null sends a POST with the body (assumed JSON)
// * Callback called with:
//    * Response code
//    * Header dictionary
//    * Body
function sendHttpRequest(serverURL, body, callback) {
  var opts = url.parse(serverURL);
  if (body) {
    opts.method = "POST";
    opts.headers = {
      "Content-Type": "application/json"
    }
  }

  function handleResponse(res) {
    var buffer = new Buffer(0);

    res.on('data', function(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
    });
    res.on('end', function() {
      DEBUG("<~~~ HTTP RESPONSE");
      DEBUG("       Code: " + res.statusCode);
      DEBUG("       Header: " + JSON.stringify(res.headers));
      DEBUG("       Body: " + util.b64enc(buffer));
      callback(res.statusCode, res.headers, buffer);
    });
  }

  DEBUG("~~~> HTTP REQUEST");
  DEBUG("       Method: " + opts.method);
  DEBUG("       URL: " + serverURL);
  DEBUG("       Body: " + body);
  var req = http.request(opts, handleResponse);
  if (body) {
    req.write(body);
  }
  req.end();
}

function jsonOrNull(buffer) {
  try {
    return JSON.parse(buffer.toString());
  } catch (e) {
    return null;
  }
}

/**
 *  createClient(serverURL)
 *
 *  Creates an ACME client object that implements ACME certificate
 *  management functions.  The only input is the URL for the ACME server.
 *
 *  Methods:
 *    * generateKeyPair(bits) => { publicKey: ..., privateKey: ...}
 *    * authorizeKeyPair(keyPair, domain) => { url: ..., authorization: ... }
 *    * issueCertificate(authorizedKeyPair, subjectKeyPair, domain)
 *          => { certificate: ...}
 *    * revokeCertificate(authorizedKeyPair, cert) => boolean
 *
 *  Notes:
 *    * All methods take a callback as final argument
 *    * Callback will be called with an object encoding the result
 *      if (result.error) { something bad happened }
 *      else { format of result is method-specific }
 **/
function createClient(authzURL, certURL) {
  return {
    newAuthzURL: authzURL,
    newCertURL:  certURL,
    authorizations: {}, // map[URL]Authorization
    certificates: {}, // map[URL]Certificate

    generateKeyPair: crypto.generateKeyPair,

    authorizeKeyPair: function(keyPair, domain, callback) {
      var tempServer = null;
      var authzURL = "";

      function handleChallenge(code, header, body) {
        if ((code != 201) || !("location" in header) || !body) {
          callback({ error: "Unacceptable challenge response" })
          DEBUG(code); DEBUG(header); DEBUG(body);
          return;
        }
        authzURL = header.location;

        var authz = jsonOrNull(body);
        if (!authz) {
          callback({ error: "New authz wasn't JSON" })
          return;
        }

        if (("status" in authz) && (authz.status != "pending")) {
          callback({ error: "New authz not in pending state" })
          return;
        }

        if (!("challenges" in authz)) {
          callback({ error: "New authz provided no challenges" })
          return;
        }

        // Respond to simpleHttps, or failing that, DVSNI
        if ("simpleHttps" in authz.challenges) {
          var challenge = authz.challenges.simpleHttps;
          var response = SimpleHttpsResponse(challenge);
          authz.challenges.simpleHttps.path = response.path;
          tempServer = SimpleHttpsServer(domain, challenge, response);
        } else if ("dvsni" in authz.challenges) {
          var challenge = authz.challenges.dvsni
          var response = DvsniResponse(challenge);
          authz.challenges.dvsni.s = response.s;
          tempServer = DvsniServer(domain, challenge, response);
        } else {
          callback({ error: "No challenges provided" })
          return;
        }

        // Start the validation server
        if (tempServer) {
          try {
            tempServer.listen(VALIDATION_SERVER_PORT);
          } catch (e) {
            // Most commonly, couldn't bind to the port
            return {
              error: "Unable to bind temp server to a port"
            }
          }
        }

        // Send the updated authz object to the authz URL
        var request = JSON.stringify(authz);
        var signedRequest = crypto.generateSignature(keyPair, new Buffer(request));
        var jsonSignedRequest = JSON.stringify(signedRequest)
        sendHttpRequest(authzURL, jsonSignedRequest, waitForFinalAuthorization);
      }

      var polls = 0;
      function waitForFinalAuthorization(code, header, body) {
        if (code == 200) {
          handleAuthorization(code, header, body);
          return;
        } else if (code >= 300) {
          callback({ error: "Got a redirect or final error code "+code });
          return;
        }

        polls += 1;
        if (polls > MAX_POLL) {
          callback({ error: "Max number of polls exceeded" });
          return;
        }

        var interval = DEFAULT_POLL_INTERVAL;
        if (("retry-after" in header) &&
            (!header["retry-after"].match(/[^0-9]/))) {

        }

        var msec = DEFAULT_POLL_INTERVAL;
        if (("retry-after" in header) &&
            (!header["retry-after"].match(/[^0-9]/))) {
          msec = parseInt(header["retry-after"]) * 1000;
          msec = (msec > MAX_POLL_INTERVAL)? MAX_POLL_INTERVAL : msec;
          msec = (msec < MIN_POLL_INTERVAL)? MIN_POLL_INTERVAL : msec;
        }

        setTimeout(function() {
          sendHttpRequest(authzURL, null, waitForFinalAuthorization);
        }, msec);
      }

      function handleAuthorization(code, header, body) {
        // Shut down validation server regardless of response
        if (tempServer) {
          tempServer.close();
        }

        var authz = jsonOrNull(body);
        if (!authz) {
          callback({ error: "Final authz wasn't JSON" });
          DEBUG("Final authz wasn't JSON");
          DEBUG(code);
          DEBUG(header);
          DEBUG(body);
          return;
        }

        this.authorizations[authzURL] = authz;
        callback({
          url: authzURL,
          authorization: authz
        });
      }

      var request = JSON.stringify({
        identifier: {
          type: "dns",
          value: domain
        }
      });
      var signedRequest = crypto.generateSignature(keyPair, new Buffer(request));
      var jsonSignedRequest = JSON.stringify(signedRequest)
      sendHttpRequest(this.newAuthzURL, jsonSignedRequest, handleChallenge);
    },

    issueCertificate: function(authorizedKeyPair, subjectKeyPair,
                               domain, callback) {
      function handleCertificate(code, headers, body) {
        if ((code != 201) || (!headers.location)) {
          callback({ error: "Unable to create certificate: "+code });
          return;
        }

        this.certificates[headers.location] = body;
        callback({
          certificate: body
        });
      }

      var csr = crypto.generateCSR(subjectKeyPair, domain);
      var request = JSON.stringify({
        csr: csr,
        authorizations: [] // TODO
      })
      var signedRequest = crypto.generateSignature(authorizedKeyPair,
                                                   new Buffer(request));
      var jsonSignedRequest = JSON.stringify(signedRequest)
      sendHttpRequest(this.newCertURL, jsonSignedRequest, handleCertificate);
    },

    revokeCertificate: function(authorizedKeyPair, certificate, callback) {
      // TODO
      /*
      function handleRevocation(response) {
        if (response.type != "revocation") {
          callback(response);
        }
        callback({ type: "success" });
      }

      var request = {
        type: "revocationRequest",
        certificate: certificate,
        signature: crypto.generateSignature(authorizedKeyPair,
                                            util.b64dec(certificate))
      };
      sendACMERequest(server, request, handleRevocation);
      */
    }
  }
}

module.exports = {
  createClient: createClient,

  // Convenience method on the client side
  getMeACertificate: function(newAuthz, newCert, domain, callback) {
    // Create a client for this URL and some key pairs
    var client = this.createClient(newAuthz, newCert);
    var authorizedKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var subjectKeyPair = client.generateKeyPair(CLIENT_KEY_SIZE);
    var recoveryKey;

    // Authorize a key pair, then request a certificate
    client.authorizeKeyPair(authorizedKeyPair, domain, function(result) {
      DEBUG("Got callback from authorizeKeyPair:");
      DEBUG(result);
      if (result.error) {
        callback(result);
        return;
      }

      client.issueCertificate(authorizedKeyPair, subjectKeyPair,
                              domain, function(result) {
        if (result.error == "error") {
          callback(result);
          return;
        }

        callback({
          authorizedKeyPair: authorizedKeyPair,
          subjectKeyPair: subjectKeyPair,
          certificate: util.b64enc(result.certificate)
        });
      });
    });
  },

  // Convenience methods for more nicely formatting crypto artifacts
  privateKeyToPem: function(privateKey) {
    return crypto.privateKeyToPem(privateKey);
  },

  certificateToPem: function(certificate) {
    return crypto.certificateToPem(certificate);
  },

  // Switch to enable local usage (one way)
  enableLocalUsage: function() {
    return enableLocalUsage();
  }
};
