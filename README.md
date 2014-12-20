Anvil - An ACME CA
==================

This is an initial implementation of an ACME-based CA.  The [ACME protocol](https://github.com/letsencrypt/acme-spec/) allows the CA to automatically verify that an applicant for a certificate actually controls an identifier, and allows a domain holder to issue and revoke certificates for his domains.

Component Model
---------------

The CA is divided into the following main components:

1. Web Front End
2. Registration Authority
3. Validation Authority
4. Certificate Authority
5. Storage Authority

This component model lets us separate the function of the CA by security context.  The Web Front End and Validation Authority need access to the Internet, which puts them at greater risk of compromise.  The Registration Authority can live without Internet connectivity, but still needs to talk to the Web Front End and Validation Authority.  The Certificate Authority need only receive instructions from the Registration Authority.

```

client <--ACME--> WFE ---+
  .                      |
  .                      +--- RA --- CA
  .                      |
client <-checks->  VA ---+

```

In Anvil, these components are represented by Go interfaces.  This allows us to have two operational modes: Consolidated and distributed.  In consolidated mode, the objects representing the different components interact directly, through function calls.  In distributed mode, each component runs in a separate process (possibly on a separate machine), and sees the other components' methods by way of a messaging layer.

Internally, the logic of the system is based around two types of objects, authorizations and certificates, mapping directly to the resources of the same name in ACME.

Requests from ACME clients result in new objects and changes objects.  The Storage Authority maintains persistent copies of the current set of objects.

Objects are also passed from one component to another on change events.  For example, when a client provides a successful response to a validation challenge, it results in a change to the corresponding validation object.  The Validation Authority forward the new validation object to the Storage Authority for storage, and to the Registration Authority for any updates to a related Authorization object.


Files
-----

* `interfaces.go` - Interfaces to the components, implemented in:
  * `web-front-end.go`
  * `registration-authority.go`
  * `validation-authority.go`
  * `certificate-authority.go`
  * `storage-authority.go`
* `objects.go` - Objects that are passed between components
* `util.go` - Miscellaneous utility methods
* `anvil_test.go` - Unit tests

If you want to run the CA, say to test client compatibility, just run the tests (`go test`).  The last test starts up the CA and runs until the Go test harness kills it (a couple of minutes).

Dependencies:

* Go platform libraries
* [GOSE](https://github.com/bifurcation/gose)


ACME Processing
---------------

```
Client -> WebFE:  challengeRequest
WebFE -> RA:      NewAuthorization(AuthorizationRequest)
RA -> RA:         [ select challenges ]
RA -> RA:         [ create Validations with challenges ]
RA -> RA:         [ create Authorization with Validations ]
RA -> SA:         Update(Authorization.ID, Authorization)
RA -> WebFE:      Authorization
WebFE -> WebFE:   [ create challenge from Authorization ]
WebFE -> WebFE:   [ generate nonce and add ]
WebFE -> Client:  challenge

----------

Client -> WebFE:  authorizationRequest
WebFE -> WebFE:   [ look up authorization based on nonce ]
WebFE -> WebFE:   [ verify authorization signature ]
WebFE -> RA:      UpdateAuthorization(Authorization)
RA -> RA:         [ add responses to authorization ]
RA -> SA:         Update(Authorization.ID, Authorization)
WebFE -> VA:      UpdateValidations(Authorization)
WebFE -> Client:  defer(authorizationID)

VA -> SA:         Update(Authorization.ID, Authorization)
VA -> RA:         OnValidationUpdate(Authorization)
RA -> RA:         [ check that validation sufficient ]
RA -> RA:         [ finalize authorization ]
RA -> SA:         Update(Authorization.ID, Authorization)
RA -> WebFE:      OnAuthorizationUpdate(Authorization)
Client -> WebFE:  statusRequest
WebFE -> Client:  error / authorization

----------

Client -> WebFE:  certificateRequest
WebFE -> WebFE:   [ verify authorization signature ]
WebFE -> RA:      NewCertificate(CertificateRequest)
RA -> RA:         [ verify CSR signature ]
RA -> RA:         [ verify authorization to issue ]
RA -> RA:         [ select CA based on issuer ]
RA -> CA:         IssueCertificate(CertificateRequest)
CA -> RA:         Certificate
RA -> CA:         [ look up ancillary data ]
RA -> WebFE:      AcmeCertificate
WebFE -> Client:  certificate

----------

Client -> WebFE:  revocationRequest
WebFE -> WebFE:   [ verify authorization signature ]
WebFE -> RA:      RevokeCertificate(RevocationRequest)
RA -> RA:         [ verify authorization ]
RA -> CA:         RevokeCertificate(Certificate)
CA -> RA:         RevocationResult
RA -> WebFE:      RevocationResult
WebFE -> Client:  revocation
```


TODO
----

* Add messaging layer to enable distributed mode
* Add monitoring / syslog
* Factor out policy layer (e.g., selection of challenges)
* Add persistent storage
