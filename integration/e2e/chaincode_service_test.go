/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package e2e

import (
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric/common/crypto/tlsgen"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/fabricconfig"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/ginkgomon"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestChaincodeAsExternalService(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chaincode As External Service Suite")
}

var _ = Describe("ChaincodeAsExternalService", func() {
	var (
		testDir                 string
		network                 *nwo.Network
		extcc                   nwo.Chaincode
		chaincodeServerAddrress string
		certFiles               []string
		process                 ifrit.Process
		extbldr                 fabricconfig.ExternalBuilder
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "e2e-chaincode-service")
		Expect(err).NotTo(HaveOccurred())
		extcc = nwo.Chaincode{
			Name:            "mycc",
			Version:         "0.0",
			Path:            components.Build("github.com/hyperledger/fabric/integration/chaincode/extcc"),
			Lang:            "extcc",
			PackageFile:     filepath.Join(testDir, "extcc.tar.gz"),
			Ctor:            `{"Args":["init","a","100","b","200"]}`,
			SignaturePolicy: `AND ('Org1MSP.member','Org2MSP.member')`,
			Sequence:        "1",
			InitRequired:    true,
			Label:           "my_extcc_chaincode",
		}

		cwd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		extbldr = fabricconfig.ExternalBuilder{
			Path: filepath.Join(cwd, "..", "externalbuilders", "extcc"),
			Name: "extcc",
		}

	})

	AfterEach(func() {
		if process != nil {
			process.Signal(syscall.SIGTERM)
			Eventually(process.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if network != nil {
			network.Cleanup()
		}
		os.RemoveAll(testDir)
	})

	Describe("basic solo network with 2 orgs and external chaincode service", func() {
		var (
			datagramReader *DatagramReader
			ccserver       ifrit.Process
		)

		BeforeEach(func() {
			datagramReader = NewDatagramReader()
			go datagramReader.Start()

			//network = nwo.New(nwo.BasicSoloWithChaincodeServers(&extcc), testDir, nil, StartPort(), components)
			network = nwo.New(nwo.BasicSolo(), testDir, nil, StartPort(), components)

			chaincodeServerAddrress = fmt.Sprintf("127.0.0.1:%d", network.ReservePort())

			tlsCA, err := tlsgen.NewCA()
			Expect(err).NotTo(HaveOccurred())
			certFiles = generateCertKeysAndConnectionFiles(tlsCA, chaincodeServerAddrress, testDir, extcc.Name)
			generateClientConnectionFile(tlsCA, chaincodeServerAddrress, testDir, extcc.Name)

			//add extcc builder
			network.ExternalBuilders = append(network.ExternalBuilders, extbldr)

			network.MetricsProvider = "statsd"
			network.StatsdEndpoint = datagramReader.Address()
			network.Profiles = append(network.Profiles, &nwo.Profile{
				Name:          "TwoOrgsBaseProfileChannel",
				Consortium:    "SampleConsortium",
				Orderers:      []string{"orderer"},
				Organizations: []string{"Org1", "Org2"},
			})
			network.Channels = append(network.Channels, &nwo.Channel{
				Name:        "baseprofilechannel",
				Profile:     "TwoOrgsBaseProfileChannel",
				BaseProfile: "TwoOrgsOrdererGenesis",
			})

			network.GenerateConfigTree()

			// package connection.json
			extcc.CodeFiles = map[string]string{
				chaincodeConnectionPath(testDir, extcc.Name): "connection.json",
			}

			for _, peer := range network.PeersWithChannel("testchannel") {
				core := network.ReadPeerConfig(peer)
				core.VM = nil
				network.WritePeerConfig(peer, core)
			}
			network.Bootstrap()

			networkRunner := network.NetworkGroupRunner()
			process = ifrit.Invoke(networkRunner)
			Eventually(process.Ready(), network.EventuallyTimeout).Should(BeClosed())
		})

		AfterEach(func() {
			if datagramReader != nil {
				datagramReader.Close()
			}
			if ccserver != nil {
				ccserver.Signal(syscall.SIGTERM)
				Eventually(ccserver.Wait(), network.EventuallyTimeout).Should(Receive())
			}
		})

		It("executes a basic solo network with 2 orgs and external chaincode service", func() {
			By("getting the orderer by name")
			orderer := network.Orderer("orderer")

			By("setting up the channel")
			network.CreateAndJoinChannel(orderer, "testchannel")
			nwo.EnableCapabilities(network, "testchannel", "Application", "V2_0", orderer, network.Peer("Org1", "peer0"), network.Peer("Org2", "peer0"))

			By("deploying the chaincode")
			nwo.DeployChaincodeWithoutInitialization(network, "testchannel", orderer, extcc)

			By("starting the chaincode service")
			extcc.SetPackageIDFromPackageFile()

			// start external chain code service
			ccrunner := chaincodeServerRunner(extcc.Path, extcc.PackageID, append([]string{extcc.PackageID, chaincodeServerAddrress}, certFiles...))
			ccserver = ifrit.Invoke(ccrunner)
			Eventually(ccserver.Ready(), network.EventuallyTimeout).Should(BeClosed())

			// init the chaincode, if required
			if extcc.InitRequired {
				By("initing the chaincode")
				nwo.InitChaincode(network, "testchannel", orderer, extcc, network.PeersWithChannel("testchannel")...)
			}

			By("getting the client peer by name")
			peer := network.Peer("Org1", "peer0")

			RunQueryInvokeQuery(network, orderer, peer, "testchannel")
			RunRespondWith(network, orderer, peer, "testchannel")
		})
	})
})

func chaincodeCertsDir(tempDir string, chaincodeID string) string {
	return filepath.Join(tempDir, "certs", chaincodeID)
}

func chaincodeConnectionDir(tempDir string, chaincodeID string) string {
	return filepath.Join(tempDir, "chaincode-connections", chaincodeID)
}

func chaincodeConnectionPath(tempDir string, chaincodeID string) string {
	return filepath.Join(chaincodeConnectionDir(tempDir, chaincodeID), "connection.json")
}

func generateCertKeysAndConnectionFiles(tlsCA tlsgen.CA, chaincodeServerAddrress string, tempDir string, chaincodeID string) []string {
	certsDir := chaincodeCertsDir(tempDir, chaincodeID)

	// Generate key files for chaincode server
	err := os.MkdirAll(certsDir, 0755)
	Expect(err).NotTo(HaveOccurred())

	serverKeyFile := filepath.Join(certsDir, "key.pem")
	serverCertFile := filepath.Join(certsDir, "cert.pem")
	clientCAFile := filepath.Join(certsDir, "clientCA.pem")

	serverPair, err := tlsCA.NewServerCertKeyPair("127.0.0.1")
	cert := serverPair.Cert
	key := serverPair.Key

	err = ioutil.WriteFile(serverKeyFile, key, 0644)
	Expect(err).NotTo(HaveOccurred())

	err = ioutil.WriteFile(serverCertFile, cert, 0644)
	Expect(err).NotTo(HaveOccurred())

	err = ioutil.WriteFile(clientCAFile, tlsCA.CertBytes(), 0644)
	Expect(err).NotTo(HaveOccurred())

	return []string{serverKeyFile, serverCertFile, clientCAFile}
}

func generateClientConnectionFile(tlsCA tlsgen.CA, chaincodeServerAddrress string, tempDir string, chaincodeID string) {
	clientPair, err := tlsCA.NewClientCertKeyPair()
	Expect(err).NotTo(HaveOccurred())
	clientKey := clientPair.Key
	clientCert := clientPair.Cert

	connectionsDir := chaincodeConnectionDir(tempDir, chaincodeID)
	err = os.MkdirAll(connectionsDir, 0755)
	Expect(err).NotTo(HaveOccurred())

	// Cannot use externalbuilder.ChaincodeServerUserData, it seems there is a bug with marsalling duration.
	// While marshalling 10 seconds gets marshalled "10" and while unmarshalling it is being read as 10 nano secons (default)
	// Will open a separate JIRA to address this
	//data := externalbuilder.ChaincodeServerUserData{
	//	Address: chaincodeServerAddrress,
	//	DialTimeout: externalbuilder.Duration{10 * time.Second},
	//	TLSRequired: true,
	//	ClientAuthRequired: true,
	//	ClientKey: string(clientKey),
	//	ClientCert: string(clientCert),
	//	RootCert: string(tlsCA.CertBytes()),
	//}
	data := struct {
		Address            string        `json:"address"`
		DialTimeout        time.Duration `json:"dial_timeout"`
		TlsRequired        bool          `json:"tls_required"`
		ClientAuthRequired bool          `json:"client_auth_required"`
		ClientKey          string        `json:"client_key"`
		ClientCert         string        `json:"client_cert"`
		RootCert           string        `json:"root_cert"`
	}{
		Address:            chaincodeServerAddrress,
		DialTimeout:        10 * time.Second,
		TlsRequired:        true,
		ClientAuthRequired: true,
		ClientKey:          string(clientKey),
		ClientCert:         string(clientCert),
		RootCert:           string(tlsCA.CertBytes()),
	}

	bdata, _ := json.Marshal(data)
	ioutil.WriteFile(chaincodeConnectionPath(tempDir, chaincodeID), bdata, 0644)
	Expect(err).NotTo(HaveOccurred())
}

func chaincodeServerRunner(path string, packageID string, args []string) *ginkgomon.Runner {
	cmd := exec.Command(path, args...)
	cmd.Env = os.Environ()

	return ginkgomon.New(ginkgomon.Config{
		Name:              packageID,
		Command:           cmd,
		StartCheck:        `Starting chaincode .* at .*`,
		StartCheckTimeout: 15 * time.Second,
	})
}
