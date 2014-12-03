go-acme
=======

This is an initial implementation of an ACME-based CA, in Go.  Right now, it is very drafty, basically a mediocre translation of node-acme.

This file is also where I'm dumping a bunch of random implementation notes as well.


Translation to reality
----------------------

The real implementation is divided into four main components:

1. Web Front End
2. Registration Authority
3. Validation Authority
4. Certificate Authority
5. Storage Authority

Internally, the logic of the system is based around three types of objects:

* authorizations, managed by the RA
* challenges, managed by the VA
* certificates, managed by the CA

Conceptually, the completion of challenges leads to the completion of authorizations, and authorizations lead to certificates.  Ultimately, the goal is to re-orient the web interface around these objects, but for now, we use them internally.

The responses to ACME messages are something like the following:

```
Client -> WebFE:  challengeRequest
WebFE -> RA:      NewAuthorization(domain)
RA -> RA:         [ select challenges ]
RA -> VA:         NewChallenges([types])
VA -> RA:         []Challenge
RA -> RA:         [ add challenges to authorization ]
RA -> SA:         WatchObjects([]Challenge)
RA -> WebFE:      Authorization
RA -> RA:         [ generate nonce and add ]
WebFE -> Client:  challenge [from Authorization]


Client -> WebFE:  authorizationRequest
WebFE -> WebFE:   [ verify signature ]
WebFE -> WebFE:   [ look up challenge indices based on nonce ]
WebFE -> VA:      UpdateChallengesWithResponses([responses])
WebFE -> Client:  defer # XXX: Where does token go

VA -> SA:         UpdateObject(challenge)
SA -> RA:         UpdateNotification(challenge)
RA -> RA:         [ look up associated authorization ]
RA -> RA:         [ check that validation sufficient ]
RA -> RA:         [ finalize authorization ]
RA -> WebFE:      ProvisionDeferredResponse(authorization)

Client -> WebFE:  certificateRequest
WebFE -> RA:      HandleCertificateRequest(AcmeCertificateRequest)
RA -> RA:         [ verify signature ]
RA -> RA:         [ verify authorization to issue ]
RA -> RA:         [ select CA based on issuer ]
RA -> CA:         IssueCertificate(CSR)
CA -> RA:         Certificate
RA -> CA:         [ look up ancillary data ]
RA -> WebFE:      AcmeCertificate
WebFE -> Client:  certificate


Client -> WebFE:  revocationRequest
WebFE -> RA:      HandleRevocationRequest(AcmeRevocationRequest)
RA -> RA:         [ verify signature ]
RA -> RA:         [ verify authorization ]
RA -> CA:         RevokeCertificate(Certificate)
CA -> RA:         RevocationResult
RA -> WebFE:      RevocationResult
WebFE -> Client:  revocation
```



RESTification
-------------

* Validation
  * identifier = { type, value }
  * status
  * Challenge
  * Response
* Authorization
  * identifier = { type, value }
  * key = jwk
  * expires = date
  * status = pending, accepted, rejected
  * challenges
    * challenge
    * response
    * status = incomplete, verifying, accepted, rejected
  * combinations
* Certificate
  * Cert itself
    * Indexes: serial, names, fingerprints
  * Raw download URI
  * Chain
  * Revocation status

* Application endpoints
  * /new-authorization
    * POST JWS containing requested identifier
    * Success: 200 w/authz; Location header for further interactions?
    * Failure: *
  * /new-certificate
  * /obj/${ID}


| -00                   | -01
|:----------------------|:----------------------------
| challengeRequest      | POST to new-authz URI
| authorizationRequest  | POST to validation URI
| certificateRequest    | POST to new-cert URI
| revocationRequest     | POST to certificate URI
