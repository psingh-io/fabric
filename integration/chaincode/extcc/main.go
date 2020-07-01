/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric/integration/chaincode/simple"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) < 6 {
		fmt.Println("usage: <package-id> <listener-address>")
		os.Exit(1)
	}

	key3, _ := ioutil.ReadFile(os.Args[3])
	cert3, _ := ioutil.ReadFile(os.Args[4])
	clientCACert3, _ := ioutil.ReadFile(os.Args[5])

	server := &shim.ChaincodeServer{
		CCID:    os.Args[1],
		Address: os.Args[2],
		CC:      new(simple.SimpleChaincode),
		TLSProps: shim.TLSProperties{
			Key:           key3,
			Cert:          cert3,
			ClientCACerts: clientCACert3,
		},
	}
	// do not modify - needed for integration test
	fmt.Printf("Starting chaincode %s at %s\n", server.CCID, server.Address)
	err := server.Start()
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
