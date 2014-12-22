#!/bin/bash

go build github.com/bifurcation/go-acme/anvil-start
./anvil-start sa &
./anvil-start ca &
./anvil-start va &
./anvil-start ra &
./anvil-start wfe &

# And when you're done, `killall anvil-start`
