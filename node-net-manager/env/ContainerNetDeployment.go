package env

import (
	"NetManager/logger"
	"NetManager/mqtt"
	"NetManager/network"
	"fmt"
	"log"
	"net"
	"runtime/debug"

	"github.com/vishvananda/netlink"
)

type ContainerDeyplomentHandler struct {
	env *Environment
}

var containerHandler *ContainerDeyplomentHandler = nil

func GetContainerNetDeployment() *ContainerDeyplomentHandler {
	if containerHandler == nil {
		logger.ErrorLogger().Fatal("Container Handler not initialized")
	}
	return containerHandler
}
func InitContainerDeployment(env *Environment) {
	containerHandler = &ContainerDeyplomentHandler{
		env: env,
	}
}

// AttachNetworkToContainer Attach a Docker container to the bridge and the current network environment
func (h *ContainerDeyplomentHandler) DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, error) {

	log.Println("MILESTOME: Deploynetwork in Container")
	env := h.env

	cleanup := func(veth *netlink.Veth) {
		_ = netlink.LinkDel(veth)
	}

	log.Println("1")
	vethIfce, err := env.createVethsPairAndAttachToBridge(sname, env.mtusize)
	if err != nil {
		go cleanup(vethIfce)
		return nil, err
	}

	log.Println("2")
	// Attach veth2 to the docker container
	logger.DebugLogger().Println("Attaching peerveth to container ")
	log.Println("2.1")
	peerVeth, err := netlink.LinkByName(vethIfce.PeerName)
	if err != nil {
		cleanup(vethIfce)
		return nil, err
	}
	log.Println("2.2")
	if err := netlink.LinkSetNsPid(peerVeth, pid); err != nil {
		cleanup(vethIfce)
		return nil, err
	}

	log.Println("3")
	//generate a new ip for this container
	ip, err := env.generateAddress()
	if err != nil {
		cleanup(vethIfce)
		return nil, err
	}

	log.Println("4")
	// set ip to the container veth
	logger.DebugLogger().Println("Assigning ip ", ip.String()+env.config.HostBridgeMask, " to container ")
	if err := env.addPeerLinkNetwork(pid, ip.String()+env.config.HostBridgeMask, vethIfce.PeerName); err != nil {
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, err
	}
	log.Println("5")
	//Add traffic route to bridge
	logger.DebugLogger().Println("Setting container routes ")
	if err = env.setContainerRoutes(pid, vethIfce.PeerName); err != nil {
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, err
	}

	env.BookVethNumber()
	log.Println("6")
	if err = env.setVethFirewallRules(vethIfce.Name); err != nil {
		env.freeContainerAddress(ip)
		cleanup(vethIfce)
		return nil, err
	}
	log.Println("7")
	if err = network.ManageContainerPorts(ip.String(), portmapping, network.OpenPorts); err != nil {
		debug.PrintStack()
		env.freeContainerAddress(ip)
		cleanup(vethIfce)
		return nil, err
	}
	log.Println("8")
	env.deployedServicesLock.Lock()
	env.deployedServices[fmt.Sprintf("%s.%d", sname, instancenumber)] = service{
		ip:          ip,
		sname:       sname,
		portmapping: portmapping,
		veth:        vethIfce,
	}
	env.deployedServicesLock.Unlock()
	return ip, nil
}

func (env *Environment) DetachContainer(sname string, instance int) {
	snameAndInstance := fmt.Sprintf("%s.%d", sname, instance)
	env.deployedServicesLock.RLock()
	s, ok := env.deployedServices[snameAndInstance]
	env.deployedServicesLock.RUnlock()
	if ok {
		_ = env.translationTable.RemoveByNsip(s.ip)
		env.deployedServicesLock.Lock()
		delete(env.deployedServices, snameAndInstance)
		env.deployedServicesLock.Unlock()
		env.freeContainerAddress(s.ip)
		_ = network.ManageContainerPorts(s.ip.String(), s.portmapping, network.ClosePorts)
		_ = netlink.LinkDel(s.veth)
		//if no interest registered delete all remaining info about the service
		if !mqtt.MqttIsInterestRegistered(sname) {
			env.RemoveServiceEntries(sname)
		}
	}
}
