/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"context"
	"fmt"
	"os"
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
		logging.Error("Error draining node: %s", err.Error())
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
	logging.Debug("Draining node")
	for {
		pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
		})
		if err != nil {
			logging.Error("Error listing pods: %s", err.Error())
			return err
		}

		if len(pods.Items) == 0 {
			fmt.Println("No pods to evict.")
			return nil
		}

		for _, pod := range pods.Items {
			// if isDaemonSetPod(&pod) {
			// 	continue
			// }

			logging.Info("Evicting pod %s in namespace %s\n", pod.Name, pod.Namespace)
			err := clientset.CoreV1().Pods("default").Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
			if err != nil {
				logging.Error("Error deleting pod %s: %v", pod.Name, err)
			}
		}

		// Wait before checking again
		// time.Sleep(10 * time.Second)
	}
}

// func drainNode(clientset *kubernetes.Clientset, nodeName string) error {
// 	pods, err := clientset.CoreV1().Pods("attestation-manager").List(context.TODO(), metav1.ListOptions{
// 		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
// 	})
// 	if err != nil {
// 		return err
// 	}

// 	for _, pod := range pods.Items {
// 		if pod.Spec.NodeName == nodeName && pod.DeletionTimestamp == nil {
// 			// if _, isDaemonSetPod := pod.ObjectMeta.Annotations["kubernetes.io/config.source"]; isDaemonSetPod {
// 			// 	continue
// 			// }

// 			// Set the pod's owner references to nil to prevent it from being recreated
// 			pod.OwnerReferences = nil
// 			if err := clientset.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{}); err != nil {
// 				return err
// 			}
// 		}
// 	}

// 	if len(pods.Items) == 0 {
// 		fmt.Println("No pods to evict.")
// 		return nil
// 	}
// 	fmt.Printf("Found %d pods to evict.\n", len(pods.Items))
// 	return nil
// }
