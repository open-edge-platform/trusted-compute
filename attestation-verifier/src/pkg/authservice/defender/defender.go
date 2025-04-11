/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This file is based on defender.go by Thomas Sileo
 * https://github.com/tsileo/defender
 */
package defender

import (
	"sync"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/external-artifacts/time/rate"
)

const Factor = 10

type Client struct {
	limiter *rate.Limiter
	expire  time.Time
	banned  bool
	key     interface{}
}

func (c *Client) Key() interface{}  { return c.key }
func (c *Client) Banned() bool      { return c.banned }
func (c *Client) Expire() time.Time { return c.expire }
func (c *Client) BanExpired() bool  { return c.banned && time.Now().After(c.expire) }

// Defender keep tracks if the `Client`s and maintains the banlist
type Defender struct {
	clients map[interface{}]*Client

	Duration    time.Duration
	BanDuration time.Duration
	Max         int

	sync.Mutex
}

// New initializes a Defender instance that will limit `max` event maximum per `duration` before banning the client for `banDuration`
func New(max int, duration, banDuration time.Duration) *Defender {
	return &Defender{
		clients:     map[interface{}]*Client{},
		Duration:    duration,
		BanDuration: banDuration,
		Max:         max,
	}
}

// BanList returns the list of banned clients
func (d *Defender) BanList() []*Client {
	l := []*Client{}
	for _, client := range d.clients {
		if client.banned {
			l = append(l, client)
		}
	}
	return l
}

func (d *Defender) Client(key interface{}) (*Client, bool) {
	d.Lock()
	defer d.Unlock()
	client, ok := d.clients[key]
	return client, ok
}

// Increment the number of event for the given client key, returns true if the client just got banned
func (d *Defender) Inc(key interface{}) bool {
	d.Lock()
	defer d.Unlock()
	now := time.Now()

	// Try to retrieve the
	if _, found := d.clients[key]; !found {
		d.clients[key] = &Client{
			key:     key,
			limiter: rate.NewLimiter(rate.Every(d.Duration), d.Max),
			expire:  now.Add(d.Duration * Factor),
		}
	}

	client := d.clients[key]

	// Check if the client is not banned anymore and the cleanup hasn't been run yet
	if client.banned && now.After(client.expire) {
		client.banned = false
	}

	// Check if client is banned
	if client.banned {
		return true
	}

	// Update the client expiration
	client.expire = now.Add(d.Duration * Factor)

	// Check the rate limiter
	banned := !client.limiter.AllowN(time.Now(), 1)

	if banned {
		// Set the client as banned
		client.banned = true

		// Set the ban duration
		client.expire = now.Add(d.BanDuration)
	}

	return banned
}

func (d *Defender) RemoveClient(key interface{}) {
	d.Lock()
	defer d.Unlock()
	if _, found := d.clients[key]; found {
		delete(d.clients, key)
	}
}

// Cleanup should be used if you want to manage the cleanup yourself, looks for CleanupTask for an automatic way
func (d *Defender) Cleanup() {
	d.Lock()
	defer d.Unlock()
	now := time.Now()
	for key, client := range d.clients {
		if now.After(client.expire) {
			delete(d.clients, key)
		}
	}
}

// CleanupTask should be run in a goroutime
func (d *Defender) CleanupTask(quit <-chan struct{}) {
	c := time.Tick(d.Duration * Factor)
	for {
		select {
		case <-quit:
			break
		case <-c:
			d.Cleanup()
		}
	}
}
