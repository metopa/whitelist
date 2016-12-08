package whitelist

// This file contains a variant of the ACL that operates on
// both IP addresses and netblocks.

import (
	"net"
)

const (
	LaunchPolicySequenced = 0
	LaunchPolicyAsync = 1
)
// A DualACL stores a list of permitted IP addresses and networks.
type DualACL interface {
	ACL

	// Add takes an IP address and adds it to the whitelist so
	// that it is now permitted.
	AddAddress(net.IP)

	// Add takes an IP network and adds it to the whitelist so
	// that it is now permitted.
	AddNetwork(*net.IPNet)

	// Remove takes an IP address and drops it from the whitelist
	// so that it is no longer permitted.
	RemoveAddress(net.IP)

	// Remove takes an IP network and drops it from the whitelist
	// so that it is no longer permitted.
	RemoveNetwork(*net.IPNet)
}

// BasicDual implements a basic dual whitelist using
// shared locks for concurrency. It must be initialised with one of the
// constructor functions. This particular implementation is
// unoptimised for large number of whitelisted networks and will not scale.
type BasicDual struct {
	Addresses HostACL `json:"addresses"`
	Networks  NetACL  `json:"networks"`
	launchPolicy int  `json:"-"`
}

// Permitted returns true if the IP has been whitelisted.
func (wl *BasicDual) Permitted(ip net.IP) bool {
	if (wl.launchPolicy == LaunchPolicySequenced) {
		return wl.Addresses.Permitted(ip) || wl.Networks.Permitted(ip)
	} else { //LaunchPolicyAsync
		res := make(chan bool, 2)
		go func() {
			res <- wl.Addresses.Permitted(ip)
		}()
		go func() {
			res <- wl.Networks.Permitted(ip)
		}()
		return <-res || <-res
	}
}

// AddAddress whitelists an IP.
func (wl *BasicDual) AddAddress(ip net.IP) {
	wl.Addresses.Add(ip)
}

// BUG(kyle): overlapping networks aren't detected.

// AddNetwork adds a new network to the whitelist. Caveat: overlapping
// networks won't be detected.
func (wl *BasicDual) AddNetwork(n *net.IPNet) {
	wl.Networks.Add(n)
}

// RemoveAddress clears the IP from the whitelist.
func (wl *BasicDual) RemoveAddress(ip net.IP) {
	wl.Addresses.Remove(ip)
}

// RemoveNetwork removes a network from the whitelist.
func (wl *BasicDual) RemoveNetwork(n *net.IPNet) {
	wl.Networks.Remove(n)
}

// NewBasicNet constructs a new basic dual whitelist.
func NewBasicDual(launchPolicy int) *BasicDual {
	return &BasicDual{
		Addresses: NewBasic(),
		Networks: NewBasicNet(),
		launchPolicy: launchPolicy,
	}
}

// StubDual allows dual whitelisting to be added into a system's
// flow without doing anything yet. All operations result in warning
// log messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
func NewStubDual() *BasicDual {
	return &BasicDual{
		Addresses: NewHostStub(),
		Networks: NewNetStub(),
		launchPolicy: LaunchPolicySequenced,
	}
}
