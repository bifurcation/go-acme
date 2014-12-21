package anvil

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/bifurcation/gose"
	"github.com/streadway/amqp"
	"log"
)

// This file defines RPC wrappers around the ${ROLE}Impl classes,
// where ROLE covers:
//  * RegistrationAuthority
//  * ValidationAuthority
//  * CertficateAuthority
//  * StorageAuthority
//
// For each one of these, the are ${ROLE}Client and ${ROLE}Server
// types.  ${ROLE}Server is to be run on the server side, as a more
// or less stand-alone component.  ${ROLE}Client is loaded by the
// code making use of the functionality.
//
// The WebFrontEnd role does not expose any functionality over RPC,
// so it doesn't need wrappers.

const (
	MethodNewAuthorization    = "NewAuthorization"    // RA
	MethodNewCertificate      = "NewCertificate"      // RA
	MethodUpdateAuthorization = "UpdateAuthorization" // RA
	MethodRevokeCertificate   = "RevokeCertificate"   // RA
	MethodOnValidationUpdate  = "OnValidationUpdate"  // RA
	MethodUpdateValidations   = "UpdateValidations"   // VA
	MethodIssueCertificate    = "IssueCertificate"    // CA
)

// RegistrationAuthorityClient / Server
//  -> NewAuthorization
//  -> NewCertificate
//  -> UpdateAuthorization
//  -> RevokeCertificate
//  -> OnValidationUpdate
type authorizationRequest struct {
	Authz Authorization
	Key   jose.JsonWebKey
}

type certificateRequest struct {
	Req CertificateRequest
	Key jose.JsonWebKey
}

func NewRegistrationAuthorityServer(serverQueue string, channel *amqp.Channel, va ValidationAuthority, ca CertificateAuthority, sa StorageAuthority) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	impl := NewRegistrationAuthorityImpl()
	impl.VA = va
	impl.CA = ca
	impl.SA = sa

	rpc.Handle(MethodNewAuthorization, func(req []byte) (response []byte) {
		var ar authorizationRequest
		err := json.Unmarshal(req, &ar)
		if err != nil {
			return
		}

		authz, err := impl.NewAuthorization(ar.Authz, ar.Key)
		if err != nil {
			return
		}

		response, err = json.Marshal(authz)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodNewCertificate, func(req []byte) (response []byte) {
		log.Printf(" [.] Entering MethodNewCertificate")
		var cr certificateRequest
		err := json.Unmarshal(req, &cr)
		if err != nil {
			log.Printf(" [!] Error unmarshaling certificate request: %s", err.Error())
			log.Printf("     JSON data: %s", string(req))
			return
		}
		log.Printf(" [.] No problem unmarshaling request")

		cert, err := impl.NewCertificate(cr.Req, cr.Key)
		if err != nil {
			log.Printf(" [!] Error issuing new certificate: %s", err.Error())
			return
		}
		log.Printf(" [.] No problem issuing new cert")

		response, err = json.Marshal(cert)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodUpdateAuthorization, func(req []byte) (response []byte) {
		var authz Authorization
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return
		}

		newAuthz, err := impl.UpdateAuthorization(authz)
		if err != nil {
			return
		}

		response, err = json.Marshal(newAuthz)
		if err != nil {
			response = []byte{}
		}
		return
	})

	rpc.Handle(MethodRevokeCertificate, func(req []byte) (response []byte) {
		// Nobody's listening, so it doesn't matter what we return
		response = []byte{}

		certs, err := x509.ParseCertificates(req)
		if err != nil || len(certs) == 0 {
			return
		}

		impl.RevokeCertificate(*certs[0])
		return
	})

	rpc.Handle(MethodOnValidationUpdate, func(req []byte) (response []byte) {
		// Nobody's listening, so it doesn't matter what we return
		response = []byte{}

		var authz Authorization
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return
		}

		impl.OnValidationUpdate(authz)
		return
	})

	return rpc, nil
}

type RegistrationAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewRegistrationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (rac RegistrationAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	rac = RegistrationAuthorityClient{rpc: rpc}
	return
}

func (rac RegistrationAuthorityClient) NewAuthorization(authz Authorization, key jose.JsonWebKey) (newAuthz Authorization, err error) {
	data, err := json.Marshal(authorizationRequest{authz, key})
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodNewAuthorization, data)
	if err != nil || len(newAuthzData) == 0 {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

func (rac RegistrationAuthorityClient) NewCertificate(cr CertificateRequest, key jose.JsonWebKey) (cert Certificate, err error) {
	data, err := json.Marshal(certificateRequest{cr, key})
	if err != nil {
		return
	}

	certData, err := rac.rpc.DispatchSync(MethodNewCertificate, data)
	if err != nil || len(certData) == 0 {
		return
	}

	err = json.Unmarshal(certData, &cert)
	return
}

func (rac RegistrationAuthorityClient) UpdateAuthorization(authz Authorization) (newAuthz Authorization, err error) {
	data, err := json.Marshal(authz)
	if err != nil {
		return
	}

	newAuthzData, err := rac.rpc.DispatchSync(MethodUpdateAuthorization, data)
	if err != nil || len(newAuthzData) == 0 {
		return
	}

	err = json.Unmarshal(newAuthzData, &newAuthz)
	return
}

func (rac RegistrationAuthorityClient) RevokeCertificate(cert x509.Certificate) (err error) {
	rac.rpc.Dispatch(MethodRevokeCertificate, cert.Raw)
	return
}

func (rac RegistrationAuthorityClient) OnValidationUpdate(authz Authorization) {
	data, err := json.Marshal(authz)
	if err != nil {
		return
	}

	rac.rpc.Dispatch(MethodOnValidationUpdate, data)
	return
}

// ValidationAuthorityClient / Server
//  -> UpdateValidations
func NewValidationAuthorityServer(serverQueue string, channel *amqp.Channel, ra RegistrationAuthority) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	impl := NewValidationAuthorityImpl()
	impl.RA = ra
	rpc.Handle(MethodUpdateValidations, func(req []byte) []byte {
		// Nobody's listening, so it doesn't matter what we return
		zero := []byte{}

		var authz Authorization
		err := json.Unmarshal(req, &authz)
		if err != nil {
			return zero
		}

		impl.UpdateValidations(authz)
		return zero
	})

	return rpc, nil
}

type ValidationAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewValidationAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (vac ValidationAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	vac = ValidationAuthorityClient{rpc: rpc}
	return
}

func (vac ValidationAuthorityClient) UpdateValidations(authz Authorization) error {
	data, err := json.Marshal(authz)
	if err != nil {
		return err
	}

	vac.rpc.Dispatch(MethodUpdateValidations, data)
	return nil
}

// CertificateAuthorityClient / Server
//  -> IssueCertificate
func NewCertificateAuthorityServer(serverQueue string, channel *amqp.Channel) (rpc *AmqpRpcServer, err error) {
	rpc = NewAmqpRpcServer(serverQueue, channel)

	impl, err := NewCertificateAuthorityImpl()
	if err != nil {
		return
	}

	rpc.Handle(MethodIssueCertificate, func(req []byte) []byte {
		zero := []byte{}

		csr, err := x509.ParseCertificateRequest(req)
		if err != nil {
			return zero // XXX
		}

		cert, err := impl.IssueCertificate(*csr)
		if err != nil {
			return zero // XXX
		}
		return cert
	})

	return rpc, nil
}

type CertificateAuthorityClient struct {
	rpc *AmqpRpcClient
}

func NewCertificateAuthorityClient(clientQueue, serverQueue string, channel *amqp.Channel) (cac CertificateAuthorityClient, err error) {
	rpc, err := NewAmqpRpcClient(clientQueue, serverQueue, channel)
	if err != nil {
		return
	}

	cac = CertificateAuthorityClient{rpc: rpc}
	return
}

func (cac CertificateAuthorityClient) IssueCertificate(csr x509.CertificateRequest) (cert []byte, err error) {
	cert, err = cac.rpc.DispatchSync(MethodIssueCertificate, csr.Raw)
	if len(cert) == 0 {
		// TODO: Better error handling
		return []byte{}, errors.New("RPC resulted in error")
	}
	return
}

// TODO StorageAuthorityClient / Server
// XXX: This will be more challenging, due to the type ambiguity
//  -> Get
//  -> Update