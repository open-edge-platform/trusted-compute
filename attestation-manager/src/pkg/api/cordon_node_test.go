package api

import (
	"context"
	"os"
	"testing"

	// "time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCordonAndDrainNode(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	nodeName := "test-node"
	os.Setenv("NODE_NAME", nodeName)

	// Create a fake node
	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
			UID:  types.UID(nodeName),
		},
	}, metav1.CreateOptions{})
	
	if err != nil {
		t.Fatalf("Failed to create fake node: %v", err)
	}

	// Create fake pods on the node
	podNames := []string{"pod1", "pod2"}
	for _, podName := range podNames {
		_, err := clientset.CoreV1().Pods("default").Create(context.TODO(), &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: podName,
				UID:  types.UID(podName),
			},
			Spec: v1.PodSpec{
				NodeName: nodeName,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("Failed to create fake pod: %v", err)
		}
	}

	// Call the function to test
	success := CordonAndDrainNode()
	if !success {
		t.Fatalf("CordonAndDrainNode failed")
	}

	// Verify the node is cordoned
	// node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get node: %v", err)
	}
	if !node.Spec.Unschedulable {
		t.Errorf("Node %s is not cordoned", nodeName)
	}

	// Verify the pods are evicted
	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		t.Fatalf("Failed to list pods: %v", err)
	}
	if len(pods.Items) != 0 {
		t.Errorf("Not all pods were evicted from node %s", nodeName)
	}
}

// func TestCordonNode(t *testing.T) {
// 	clientset := fake.NewSimpleClientset()
// 	nodeName := "test-node"

// 	// Create a fake node
// 	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), &v1.Node{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name: nodeName,
// 			UID:  types.UID(nodeName),
// 		},
// 	}, metav1.CreateOptions{})
// 	if err != nil {
// 		t.Fatalf("Failed to create fake node: %v", err)
// 	}

// 	// Call the function to test
// 	err = cordonNode(clientset, nodeName)
// 	if err != nil {
// 		t.Fatalf("cordonNode failed: %v", err)
// 	}

// 	// Verify the node is cordoned
// 	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
// 	if err != nil {
// 		t.Fatalf("Failed to get node: %v", err)
// 	}
// 	if !node.Spec.Unschedulable {
// 		t.Errorf("Node %s is not cordoned", nodeName)
// 	}
// }

// func TestDrainNode(t *testing.T) {
// 	clientset := fake.NewSimpleClientset()
// 	nodeName := "test-node"

// 	// Create a fake node
// 	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), &v1.Node{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name: nodeName,
// 			UID:  types.UID(nodeName),
// 		},
// 	}, metav1.CreateOptions{})
// 	if err != nil {
// 		t.Fatalf("Failed to create fake node: %v", err)
// 	}

// 	// Create fake pods on the node
// 	podNames := []string{"pod1", "pod2"}
// 	for _, podName := range podNames {
// 		_, err := clientset.CoreV1().Pods("default").Create(context.TODO(), &v1.Pod{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Name: podName,
// 				UID:  types.UID(podName),
// 			},
// 			Spec: v1.PodSpec{
// 				NodeName: nodeName,
// 			},
// 		}, metav1.CreateOptions{})
// 		if err != nil {
// 			t.Fatalf("Failed to create fake pod: %v", err)
// 		}
// 	}

// 	// Call the function to test
// 	err = drainNode(clientset, nodeName)
// 	if err != nil {
// 		t.Fatalf("DrainNode failed: %v", err)
// 	}

// 	// Verify the pods are evicted
// 	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{
// 		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to list pods: %v", err)
// 	}
// 	if len(pods.Items) != 0 {
// 		t.Errorf("Not all pods were evicted from node %s", nodeName)
// 	}
// }
// func TestDrainNode(t *testing.T) {
// 	clientset := fake.NewSimpleClientset()
// 	nodeName := "test-node"

// 	// Create a fake node
// 	_, err := clientset.CoreV1().Nodes().Create(context.TODO(), &v1.Node{
// 		ObjectMeta: metav1.ObjectMeta{
// 			Name: nodeName,
// 			UID:  types.UID(nodeName),
// 		},
// 	}, metav1.CreateOptions{})
// 	if err != nil {
// 		t.Fatalf("Failed to create fake node: %v", err)
// 	}

// 	// Create fake pods on the node
// 	podNames := []string{"pod1", "pod2"}
// 	for _, podName := range podNames {
// 		_, err := clientset.CoreV1().Pods("default").Create(context.TODO(), &v1.Pod{
// 			ObjectMeta: metav1.ObjectMeta{
// 				Name: podName,
// 				UID:  types.UID(podName),
// 			},
// 			Spec: v1.PodSpec{
// 				NodeName: nodeName,
// 			},
// 		}, metav1.CreateOptions{})
// 		if err != nil {
// 			t.Fatalf("Failed to create fake pod: %v", err)
// 		}
// 	}

// 	// Call the function to test
// 	err = drainNode(clientset, nodeName)
// 	if err != nil {
// 		t.Fatalf("DrainNode failed: %v", err)
// 	}

// 	// Verify the pods are evicted
// 	pods, err := clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{
// 		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
// 	})
// 	if err != nil {
// 		t.Fatalf("Failed to list pods: %v", err)
// 	}
// 	if len(pods.Items) != 0 {
// 		t.Errorf("Not all pods were evicted from node %s", nodeName)
// 		}
// 	}
