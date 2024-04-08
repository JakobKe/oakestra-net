package env

import "net"

const (
	CONTAINER_RUNTIME = "container"
)

type NetDeploymentInterface interface {
	DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error)
}

func GetNetDeployment(handler string) NetDeploymentInterface {
	switch handler {
	case CONTAINER_RUNTIME:
		return GetContainerNetDeployment()
	}
	return nil
}
