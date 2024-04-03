#!/bin/bash

echo -e "Starting script for building and transferring the node-netmanager executable to all Kubernetes nodes\n"


echo "Building..."
GOOS=linux GOARCH=amd64 go build -o node-netmanager


scp ./node-netmanager oakestra-env:/home/ubuntu/temp/node-netmanager
echo "Transferring..."

for node in {1..2}; do
    for cluster in {1..2}; do
        ssh oakestra-env "ssh kubernetes-${cluster}-${node} 'mkdir -p temp' >/dev/null 2>&1"
        ssh oakestra-env "scp /home/ubuntu/temp/node-netmanager kubernetes-${cluster}-${node}:/home/ubuntu/"
    done
done

echo "node-netmanager executable successfully transferred to Kubernetes cluster nodes."
