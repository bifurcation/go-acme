var crypto = require("./crypto-util");

var keyPair = crypto.generateKeyPair(512);

var payload = new Buffer("hello, world!");
var jws = crypto.generateSignature(keyPair, payload);
console.log(JSON.stringify(jws));

console.log(crypto.verifySignature(jws));
