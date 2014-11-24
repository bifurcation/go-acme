go-acme
=======

This is an initial implementation of an ACME-based CA, in Go.  Right now, it is very drafty, basically a mediocre translation of node-acme.

* `acme.go` has the web front end logic
* `jwk.go` and `jws.go` handle JOSE bits
* `util.go` has miscellaneous utility functions
* `acme_test.go` has ... tests!  Calling `go test` is the way to run this module right now.
