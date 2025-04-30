/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a server for Greeter service.
package main

import (
	pb "attestation-manager/attestationstatusmgr"
	"context"
	"crypto/tls"

	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

var (
	port      = flag.Int("port", 50051, "The server port")
	jwtSecret = []byte("your-256-bit-secret") // Replace with your actual secret
)

// var (
// 	port = flag.Int("port", 50051, "The server port")
// )

// server is used to implement helloworld.GreeterServer.
type server struct {
	pb.UnimplementedAttestationmgrServer
}

// SayHello implements helloworld.GreeterServer
func (s *server) UpdateInstanceAttestationStatusByHostGuid(ctx context.Context, in *pb.UpdateInstanceAttestationStatusByHostGuidRequest) (*pb.UpdateInstanceAttestationStatusByHostGuidResponse, error) {
	// Extract JWT token from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing metadata")
	}
	// Log the incoming metadata for debugging
    log.Printf("Incoming metadata: %v", md)
	tokenString := md["authorization"]
	fmt.Print("token from client   ", tokenString)
	if len(tokenString) == 0 {
		return nil, fmt.Errorf("######missing authorization token from server")
	}

	// Verify the JWT token
	token, err := jwt.Parse(strings.TrimPrefix(tokenString[0], "Bearer "), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	log.Printf("Received: %v", in.HostGuid)
	log.Printf("Received HostGuid: %s", in.HostGuid)
	log.Printf("Received AttestationStatus: %s", in.AttestationStatus)
	log.Printf("Received Attestation Status Detail: %s", in.AttestationStatusDetail)

	response := &pb.UpdateInstanceAttestationStatusByHostGuidResponse{Message: "Hello " + in.HostGuid}
	log.Printf("Sending response: %v", response.Message)

	return response, nil
}

func main() {
	flag.Parse()

	cert, err := tls.LoadX509KeyPair("cert164/server-cert.pem", "cert164/server-key.pem")
	if err != nil {
		log.Fatalf("failed to load server key pair: %s", err)
	}
	// Load CA certificate
	caCert, err := os.ReadFile("cert164/ca-cert.pem")
	if err != nil {
		log.Fatalf("failed to read CA certificate: %s", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatalf("failed to append CA certificate")
	}

	// Create the TLS credentials
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		// ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
		ClientAuth: tls.NoClientCert, // Disable mTLS
	}
	// Create the credentials
	// config := &tls.Config{
	// 	Certificates: []tls.Certificate{cert},
	// 	ClientAuth:   tls.NoClientCert,
	// }

	creds := credentials.NewTLS(config)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	fmt.Println("Server started on port 50051", creds)
	s := grpc.NewServer(grpc.Creds(creds))
	// s := grpc.NewServer()
	pb.RegisterAttestationmgrServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
