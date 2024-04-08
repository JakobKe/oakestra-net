package main

import (
	"NetManager/env"
	"NetManager/handlers"
	"NetManager/logger"
	"NetManager/mqtt"
	"NetManager/network"
	"NetManager/proxy"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/tkanos/gonfig"
)

type undeployRequest struct {
	Servicename    string `json:"serviceName"`
	Instancenumber int    `json:"instanceNumber"`
}

type registerRequest struct {
	ClientID string `json:"client_id"`
}

type DeployResponse struct {
	ServiceName string `json:"serviceName"`
	NsAddress   string `json:"nsAddress"`
}

type netConfiguration struct {
	NodePublicAddress string
	NodePublicPort    string
	ClusterUrl        string
	ClusterMqttPort   string
}

func handleRequests(port int) {
	netRouter := mux.NewRouter().StrictSlash(true)
	netRouter.HandleFunc("/register", register).Methods("POST")
	netRouter.HandleFunc("/docker/deploy", dockerDeploy).Methods("POST")

	handlers.RegisterAllManagers(&Env, &WorkerID, Configuration.NodePublicAddress, Configuration.NodePublicPort, netRouter)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), netRouter))
}

func handleRequestsCNIPlugin(port int) {
	netRouter := mux.NewRouter().StrictSlash(true)
	handlers.RegisterAllManagers(&Env, &WorkerID, Configuration.NodePublicAddress, Configuration.NodePublicPort, netRouter)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), netRouter))
}

var Env env.Environment
var Proxy proxy.GoProxyTunnel
var WorkerID string
var Configuration netConfiguration

func dockerDeploy(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP request - /docker/deploy ")
	writer.WriteHeader(299)
	_, _ = writer.Write([]byte("DEPRECATED API"))
}

/*
Endpoint: /register
Usage: used to initialize the Network manager. The network manager must know his local subnetwork.
Method: POST
Request Json:

	{
		client_id:string # id of the worker node
	}

Response: 200 or Failure code
*/
func register(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP request - /register ")

	reqBody, _ := io.ReadAll(request.Body)
	var requestStruct registerRequest
	err := json.Unmarshal(reqBody, &requestStruct)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}
	log.Println(requestStruct)

	//drop the request if the node is already initialized
	if WorkerID != "" {
		if WorkerID == requestStruct.ClientID {
			log.Printf("Node already initialized")
			writer.WriteHeader(http.StatusOK)
		} else {
			log.Printf("Attempting to re-initialize a node with a different worker ID")
			writer.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	WorkerID = requestStruct.ClientID

	//initialize mqtt connection to the broker
	mqtt.InitNetMqttClient(requestStruct.ClientID, Configuration.ClusterUrl, Configuration.ClusterMqttPort)

	//initialize the proxy tunnel
	Proxy = proxy.New()
	Proxy.Listen()

	//initialize the Env Manager
	Env = *env.NewEnvironmentClusterConfigured(Proxy.HostTUNDeviceName)

	Proxy.SetEnvironment(&Env)

	writer.WriteHeader(http.StatusOK)
}

/*
Automatic register in k8s cluster
*/
func automaticRegister() error {
	log.Println("Start automatic register")

	//c.GetWorkerID()

	// clientID := "test-k8s-1" //  c.GetWorkerID() //" // This will have to be dealt with later
	// if err != nil {
	// 	return fmt.Errorf("k8sclient error: %v", err)
	// }

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Fehler beim Abrufen des Hostnamens:", err)
		return err
	}

	//drop the request if the node is already initialized
	// if WorkerID != "" {
	// 	if WorkerID == clientID {
	// 		log.Printf("Node already initialized")
	// 	} else {
	// 		log.Printf("Attempting to re-initialize a node with a different worker ID")
	// 	}
	// 	return nil
	// }

	clientID := hostname + "-" + Configuration.NodePublicAddress
	WorkerID = clientID

	log.Printf("START MQTT")
	//initialize mqtt connection to the broker
	mqtt.InitNetMqttClient(clientID, Configuration.ClusterUrl, Configuration.ClusterMqttPort)

	log.Printf("START PROXY")
	//initialize the proxy tunnel
	Proxy = proxy.New()
	log.Printf("START PROXY LISTENING")
	Proxy.Listen()

	log.Printf("START ENV")
	//initialize the Env Manager
	Env = *env.NewEnvironmentClusterConfigured(Proxy.HostTUNDeviceName)

	Proxy.SetEnvironment(&Env)
	return nil
}

func main() {

	cfgFile := flag.String("cfg", "/etc/netmanager/netcfg.json", "Set a cluster IP")
	localPort := flag.Int("p", 6000, "Default local port of the NetManager")
	debugMode := flag.Bool("D", false, "Debug mode, it enables debug-level logs")
	flag.Parse()

	err := gonfig.GetConf(*cfgFile, &Configuration)
	if err != nil {
		log.Fatal(errors.Wrap(err, "failed to load configuration"))
	}

	//c, _ := kubenetesclient.NewKubernetesClient()
	// hostIP := "192.168.123.196" //c.GetHostIP()
	// if err != nil {
	// 	log.Fatal(errors.Wrap(err, "failed to load hostip"))
	// }

	// Configuration.NodePublicAddress = hostIP
	// Configuration.NodePublicPort = os.Getenv("NODE_PORT")
	// Configuration.ClusterMqttPort = os.Getenv("MOSQUITTO_SVC_SERVICE_PORT")
	// Configuration.ClusterUrl = os.Getenv("MOSQUITTO_SVC_SERVICE_HOST")
	// TODO die ClusterURL ist so nicht ganz richtig. Das läuft ja nicht mehr im "Cluster"
	// Eigentlich ist es die MQTT Broker URL.

	if *debugMode {
		logger.SetDebugMode()
	}
	network.IptableFlushAll()

	log.Println("NetManager started. Start Registration of Node.")

	automaticRegister()

	// Start manager for listenints
	handleRequestsCNIPlugin(*localPort)
}
