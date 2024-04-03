package kubenetesclient

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type KubernetesClient struct {
	dynamicClient     *dynamic.DynamicClient
	clientSet         *kubernetes.Clientset
	resourceNamespace string
}

func NewKubernetesClient() (KubernetesClient, error) {

	var config *rest.Config
	var err error

	config, err = rest.InClusterConfig()
	if err != nil {
		fmt.Printf("Error building in-cluster kubeconfig: %v\n", err)
		os.Exit(1)
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return KubernetesClient{}, fmt.Errorf("configure kubernetes client failed: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return KubernetesClient{}, fmt.Errorf("configure dynamicClient failed: %w", err)
	}

	return KubernetesClient{
		dynamicClient:     dynamicClient,
		clientSet:         clientSet,
		resourceNamespace: "oakestra",
	}, nil
}

func (c KubernetesClient) GetWorkerID() (string, error) {
	nodeName := os.Getenv("HOSTNAME")
	nodeIP, _ := c.GetHostIP()

	return nodeName + "/" + nodeIP, nil
}

func (c KubernetesClient) GetHostIP() (string, error) {
	// Hostname = Nodename (pods runs in privileged mode)
	nodeName := os.Getenv("HOSTNAME")
	addressType := corev1.NodeInternalIP

	node, err := c.clientSet.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
	if err != nil {
		panic(err.Error())
	}

	var ip string
	for _, addr := range node.Status.Addresses {
		if addr.Type == addressType {
			ip = addr.Address
			break
		}
	}

	return ip, nil
}
