package env

import "net"

const (
	CONTAINER_RUNTIME = "container"
)

type NetDeploymentInterface interface {
<<<<<<< HEAD
	DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error)
=======
	DeployNetwork(pid int, netns string, sname string, instancenumber int, portmapping string) (net.IP, error)
>>>>>>> ec15089 (Adjustements to work in Kubernetes env)
}

func GetNetDeployment(handler string) NetDeploymentInterface {
	switch handler {
	case CONTAINER_RUNTIME:
		return GetContainerNetDeployment()
	}
	return nil
}
