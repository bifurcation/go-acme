// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"github.com/bifurcation/go-acme"
	"github.com/codegangsta/cli"
	"github.com/streadway/amqp"
	"net/http"
	"os"
)

// Exit and print error message if we encountered a problem
func failOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// This is the same as amqpConnect in anvil, but with even
// more aggressive error dropping
func amqpChannel(url string) (ch *amqp.Channel) {
	conn, err := amqp.Dial(url)
	failOnError(err, "Unable to connect to AMQP server")

	ch, err = conn.Channel()
	failOnError(err, "Unable to establish channel to AMQP server")
	return
}

// Start the server and wait around
func runForever(server *anvil.AmqpRpcServer) {
	forever := make(chan bool)
	server.Start()
	fmt.Fprintf(os.Stderr, "Server running...\n")
	<-forever
}

func main() {
	app := cli.NewApp()
	app.Name = "anvil-start"
	app.Usage = "Command-line utility to start Anvil's servers in stand-alone mode"
	app.Version = "0.0.0"

	// Server URL hard-coded for now
	amqpServerURL := "amqp://guest:guest@localhost:5672"

	// One command per element of the system
	// * WebFrontEnd
	// * RegistrationAuthority
	// * ValidationAuthority
	// * CertificateAuthority
	// * StorageAuthority
	//
	// Once started, we just run until killed
	//
	// AMQP queue names are hard-coded for now
	app.Commands = []cli.Command{
		{
			Name:  "wfe",
			Usage: "Start the WebFrontEnd",
			Action: func(c *cli.Context) {
				// Create necessary clients
				ch := amqpChannel(amqpServerURL)

				rac, err := anvil.NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
				failOnError(err, "Unable to create RA client")

				sac, err := anvil.NewStorageAuthorityClient("SA.client", "SA.server", ch)
				failOnError(err, "Unable to create SA client")

				// Create the front-end and wire in its resources
				wfe := anvil.NewWebFrontEndImpl()
				wfe.RA = &rac
				wfe.SA = &sac

				// Connect the front end to HTTP
				authority := "localhost:4000"
				authzPath := "/acme/authz/"
				certPath := "/acme/cert/"
				wfe.SetAuthzBase("http://" + authority + authzPath)
				wfe.SetCertBase("http://" + authority + certPath)
				http.HandleFunc("/acme/new-authz", wfe.NewAuthz)
				http.HandleFunc("/acme/new-cert", wfe.NewCert)
				http.HandleFunc("/acme/authz/", wfe.Authz)
				http.HandleFunc("/acme/cert/", wfe.Cert)
				http.ListenAndServe(authority, nil)
			},
		},
		{
			Name:  "sa",
			Usage: "Start the CertificateAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(amqpServerURL)

				cas, err := anvil.NewCertificateAuthorityServer("CA.server", ch)
				failOnError(err, "Unable to create CA server")
				runForever(cas)
			},
		},
		{
			Name:  "ca",
			Usage: "Start the StorageAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(amqpServerURL)

				sas := anvil.NewStorageAuthorityServer("SA.server", ch)
				runForever(sas)
			},
		},
		{
			Name:  "va",
			Usage: "Start the ValidationAuthority",
			Action: func(c *cli.Context) {
				ch := amqpChannel(amqpServerURL)

				rac, err := anvil.NewRegistrationAuthorityClient("RA.client", "RA.server", ch)
				failOnError(err, "Unable to create RA client")

				vas, err := anvil.NewValidationAuthorityServer("VA.server", ch, &rac)
				failOnError(err, "Unable to create VA server")
				runForever(vas)
			},
		},
		{
			Name:  "ra",
			Usage: "Start the RegistrationAuthority",
			Action: func(c *cli.Context) {
				// TODO
				ch := amqpChannel(amqpServerURL)

				vac, err := anvil.NewValidationAuthorityClient("VA.client", "VA.server", ch)
				failOnError(err, "Unable to create VA client")

				cac, err := anvil.NewCertificateAuthorityClient("CA.client", "CA.server", ch)
				failOnError(err, "Unable to create CA client")

				sac, err := anvil.NewStorageAuthorityClient("SA.client", "SA.server", ch)
				failOnError(err, "Unable to create SA client")

				ras, err := anvil.NewRegistrationAuthorityServer("RA.server", ch, &vac, &cac, &sac)
				failOnError(err, "Unable to create RA server")
				runForever(ras)
			},
		},
	}

	err := app.Run(os.Args)
	failOnError(err, "Failed to run application")
}
