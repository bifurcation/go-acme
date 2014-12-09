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

In Anvil, these components are represented by Go interfaces.  This allows us to have two operational modes: Consolidated and distributed.  In consolidated mode, the objects representing the different components interact directly, through function calls.  In distributed mode, each component runs in a separate process (possibly on a separate machine), and sees the other components' methods by way of a messaging layer.

Internally, the logic of the system is based around three types of objects:

* authorizations, managed by the RA
* validations, managed by the VA
* certificates, managed by the CA

Conceptually, the completion of challenges leads to the completion of authorizations, and authorizations lead to certificates.  Ultimately, we may re-orient the ACME protocol around these objects, but for now, we use them internally.

Requests from ACME clients result in new objects and changes objects.  The Storage Authority maintains persistent copies of the current set of objects.  Validation objects have no life of their own, however; they exist only inside authorization objects.

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
* `jwk.go` - An object representation for JSON Web Key objects
* `anvil_test.go` - Unit tests


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
WebFE -> WebFE:   [ add responses to authorization ]
WebFE -> SA:      Update(Authorization.ID, Authorization)
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

* Add messaging layer
* Add authority monitor
* Factor out policy layer (e.g., selection of challenges)
* Add persistent storage
