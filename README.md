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

The responses to ACME messages are something like the following:

```
Client -> WebFE:  challengeRequest
WebFE -> RA:      HandleChallengeRequest(AcmeChallengeRequest)
RA -> RA:         [ generate nonce ]
RA -> RA:         [ select challenges ]
RA -> WebFE:      AcmeChallenge
WebFE -> Client:  challenge


Client -> WebFE:  authorizationRequest
WebFE -> RA:      HandleAuthorizationRequest(AcmeAuthorizationRequest)
RA -> RA:         [ verify signature ]
RA -> RA:         [ generate deferralID ]
RA -> RA:         [ mark (domain,key) as pending deferralID ]
RA -> VA:         Validate(challenge, response)
VA -> RA:         validationID
RA -> WebFE:      AcmeDefer{deferralID}
WebFE -> Client:  defer

VA -> RA:         ValidationResults(validationID, success)
RA -> RA:         [ validationID -> deferralID ]
RA -> RA:         [ check that validation sufficient ]
RA -> RA:         [ store authorization for (domain,key) ]
RA -> WebFE:      ProvisionDeferredResponse(deferralID, AcmeAuthorization)
Client -> WebFE:  statusRequest
WebFE -> Client:  authorization


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




