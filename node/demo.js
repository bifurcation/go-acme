var acme = require("./acme");

acme.enableLocalUsage();

var newAuthz = "http://localhost:4000/acme/new-authz";
var newCert  = "http://localhost:4000/acme/new-cert";
acme.getMeACertificate(newAuthz, newCert, "example.com", function(x) {
  console.log("Result of getMeACertificate:");
  console.log(x);
});
