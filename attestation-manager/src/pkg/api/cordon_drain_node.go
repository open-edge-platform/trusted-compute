/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	// v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"

	// "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	// "k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/rest"
	// "k8s.io/client-go/util/retry"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

func CordonAndDrainNode() bool {

	logging.Debug("Cordon and drain node started")
	nodeName := os.Getenv("NODE_NAME")
	logging.Info("Cordoning ,Node name: ", nodeName)
	// Load kubeconfig
	// kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
	// config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	// if err != nil {
	// 	log.Fatalf("Error building kubeconfig: %s", err.Error())
	// }
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.Error("Error building in-cluster config: %s", err.Error())
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.Error("Error creating Kubernetes client: %s", err.Error())
	}

	// Cordon the node
	if err := cordonNode(clientset, nodeName); err != nil {
		logging.Error("Error cordoning node: %s", err.Error())
		return false
	}
	logging.Debug("Node cordoned successfully")
	// Sleep for a while before the next attestation check
	logging.Debug("Sleeping for 1 minutes and calling drainNode()")

	time.Sleep(1 * time.Minute)
	// Drain the node
	if err := drainNode(clientset, nodeName); err != nil {
		logging.Error(fmt.Sprintf("Error draining node: %s", err.Error()))
		return false
	} else {
		return true
	}

}

func cordonNode(clientset *kubernetes.Clientset, nodeName string) error {
	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	node.Spec.Unschedulable = true
	_, err = clientset.CoreV1().Nodes().Update(context.TODO(), node, metav1.UpdateOptions{})
	return err
}

func drainNode(clientset *kubernetes.Clientset, nodeName string) error {
	logging.Debug("Draining node started")

	// Define namespaces to skip initially
	skippedNamespaces := map[string]bool{
		"calico-system":   true,
		"cattle-system":   true,
		"kube-system":     true,
		"trusted-compute": true,
	}

	namespaces, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		logging.Error(fmt.Sprintf("Error listing namespaces: %s", err.Error()))
		return err
	}

	// Delete all pods in non-skipped namespaces
	for _, namespace := range namespaces.Items {
		if skippedNamespaces[namespace.Name] {
			logging.Info(fmt.Sprintf("Skipping namespace: %s", namespace.Name))
			continue
		}
		logging.Info(fmt.Sprintf("Processing namespace: %s", namespace.Name))

		pods, err := clientset.CoreV1().Pods(namespace.Name).List(context.TODO(), metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
		})
		if err != nil {
			logging.Error(fmt.Sprintf("Error listing pods in namespace %s: %s", namespace.Name, err.Error()))
			continue
		}

		for _, pod := range pods.Items {
			logging.Info(fmt.Sprintf("Deleting pod %s in namespace %s", pod.Name, namespace.Name))
			err := clientset.CoreV1().Pods(namespace.Name).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
			if err != nil {
				logging.Error(fmt.Sprintf("Error deleting pod %s in namespace %s: %v", pod.Name, namespace.Name, err))
			}
		}
	}

	// Handle "trusted-compute" namespace separately
	trustedComputePods, err := clientset.CoreV1().Pods("trusted-compute").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		logging.Error(fmt.Sprintf("Error listing pods in namespace trusted-compute: %s", err.Error()))
		return err
	}

	time.Sleep(1 * time.Minute)
	for _, pod := range trustedComputePods.Items {
		logging.Info(fmt.Sprintf("Found pod %s in namespace trusted-compute", pod.Name))
		if strings.HasPrefix(pod.Name, "attestation-manager") {
			logging.Info(fmt.Sprintf("Skipping pod %s in namespace trusted-compute", pod.Name))
			continue
		}
		logging.Info(fmt.Sprintf("Deleting pod %s in namespace trusted-compute", pod.Name))
		err := clientset.CoreV1().Pods("trusted-compute").Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			logging.Error(fmt.Sprintf("Error deleting pod %s in namespace trusted-compute: %v", pod.Name, err))
		}
	}

	// Delete pods in skipped namespaces
	for namespace := range skippedNamespaces {
		logging.Info(fmt.Sprintf("Deleting pods in skipped namespace: %s", namespace))
		pods, err := clientset.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
		})
		if err != nil {
			logging.Error(fmt.Sprintf("Error listing pods in namespace %s: %s", namespace, err.Error()))
			continue
		}
		time.Sleep(1 * time.Minute)
		for _, pod := range pods.Items {
			logging.Info(fmt.Sprintf("Deleting pod %s in namespace %s", pod.Name, namespace))
			err := clientset.CoreV1().Pods(namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
			if err != nil {
				logging.Error(fmt.Sprintf("Error deleting pod %s in namespace %s: %v", pod.Name, namespace, err))
			}
		}
	}

	logging.Info("All pods deleted successfully")
	return nil
}
