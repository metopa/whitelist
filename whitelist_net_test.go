package whitelist

import (
	"encoding/json"
	"net"
	"testing"
)

func TestMarshalCompatNet(t *testing.T) {
	tv := map[string]*BasicNet{
		"test-a": NewBasicNet(),
		"test-b": NewBasicNet(),
	}

	_, n, err := net.ParseCIDR("192.168.3.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	_, n, err = net.ParseCIDR("192.168.7.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	out, err := json.Marshal(tv)
	if err != nil {
		t.Fatalf("%v", err)
	}

	var tvPrime map[string]*BasicNet
	err = json.Unmarshal(out, &tvPrime)

	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(tvPrime["test-a"].whitelist) != 2 {
		t.Fatalf("Expected whitelist to have 2 addresses, but have %d", len(tvPrime["test-a"].whitelist))
	}

	if len(tvPrime["test-b"].whitelist) != 0 {
		t.Fatalf("Expected whitelist to have 0 addresses, but have %d", len(tvPrime["test-b"].whitelist))
	}

	if !checkIPString(tvPrime["test-a"], "192.168.3.1", t) || !checkIPString(tvPrime["test-a"], "192.168.7.255", t) {
		t.Fatal("whitelist should have permitted address")
	}

	if checkIPString(tvPrime["test-b"], "192.168.3.1", t) {
		t.Fatal("whitelist should have denied address")
	}
}

func TestMarshalNewNet(t *testing.T) {
	tv := map[string]*BasicNet{
		"test-a": NewBasicNet2(JsonFormatNew),
		"test-b": NewBasicNet2(JsonFormatNew),
	}

	_, n, err := net.ParseCIDR("192.168.3.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	_, n, err = net.ParseCIDR("192.168.7.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	out, err := json.Marshal(tv)

	if err != nil {
		t.Fatalf("%v", err)
	}

	var tvPrime map[string]*BasicNet
	err = json.Unmarshal(out, &tvPrime)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(tvPrime["test-a"].whitelist) != 2 {
		t.Fatalf("Expected whitelist to have 2 addresses, but have %d", len(tvPrime["test-a"].whitelist))
	}

	if len(tvPrime["test-b"].whitelist) != 0 {
		t.Fatalf("Expected whitelist to have 0 addresses, but have %d", len(tvPrime["test-b"].whitelist))
	}

	if !checkIPString(tvPrime["test-a"], "192.168.3.1", t) || !checkIPString(tvPrime["test-a"], "192.168.7.255", t) {
		t.Fatal("whitelist should have permitted address")
	}

	if checkIPString(tvPrime["test-b"], "192.168.3.1", t) {
		t.Fatal("whitelist should have denied address")
	}
}

func TestMarshalCompatNetIndent(t *testing.T) {
	tv := map[string]*BasicNet{
		"test-a": NewBasicNet(),
		"test-b": NewBasicNet(),
	}

	_, n, err := net.ParseCIDR("192.168.3.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	_, n, err = net.ParseCIDR("192.168.7.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	out, err := json.MarshalIndent(tv, "", "  ")
	if err != nil {
		t.Fatalf("%v", err)
	}

	var tvPrime map[string]*BasicNet
	err = json.Unmarshal(out, &tvPrime)

	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(tvPrime["test-a"].whitelist) != 2 {
		t.Fatalf("Expected whitelist to have 2 addresses, but have %d", len(tvPrime["test-a"].whitelist))
	}

	if len(tvPrime["test-b"].whitelist) != 0 {
		t.Fatalf("Expected whitelist to have 0 addresses, but have %d", len(tvPrime["test-b"].whitelist))
	}

	if !checkIPString(tvPrime["test-a"], "192.168.3.1", t) || !checkIPString(tvPrime["test-a"], "192.168.7.255", t) {
		t.Fatal("whitelist should have permitted address")
	}

	if checkIPString(tvPrime["test-b"], "192.168.3.1", t) {
		t.Fatal("whitelist should have denied address")
	}
}

func TestMarshalNewNetIndent(t *testing.T) {
	tv := map[string]*BasicNet{
		"test-a": NewBasicNet2(JsonFormatNew),
		"test-b": NewBasicNet2(JsonFormatNew),
	}

	_, n, err := net.ParseCIDR("192.168.3.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	_, n, err = net.ParseCIDR("192.168.7.0/24")
	if err != nil {
		t.Fatalf("%v", err)
	}
	tv["test-a"].Add(n)

	out, err := json.MarshalIndent(tv, "", "  ")

	if err != nil {
		t.Fatalf("%v", err)
	}

	var tvPrime map[string]*BasicNet
	err = json.Unmarshal(out, &tvPrime)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(tvPrime["test-a"].whitelist) != 2 {
		t.Fatalf("Expected whitelist to have 2 addresses, but have %d", len(tvPrime["test-a"].whitelist))
	}

	if len(tvPrime["test-b"].whitelist) != 0 {
		t.Fatalf("Expected whitelist to have 0 addresses, but have %d", len(tvPrime["test-b"].whitelist))
	}

	if !checkIPString(tvPrime["test-a"], "192.168.3.1", t) || !checkIPString(tvPrime["test-a"], "192.168.7.255", t) {
		t.Fatal("whitelist should have permitted address")
	}

	if checkIPString(tvPrime["test-b"], "192.168.3.1", t) {
		t.Fatal("whitelist should have denied address")
	}
}

func TestMarshalNetFail(t *testing.T) {
	wl := NewBasicNet()
	badInput := `192.168.3.1/24,127.0.0.1/32`
	if err := wl.UnmarshalJSON([]byte(badInput)); err == nil {
		t.Fatal("Expected failure unmarshaling bad JSON input.")
	}

	badInput = `"192.168.3.1,127.0.0.256"`
	if err := wl.UnmarshalJSON([]byte(badInput)); err == nil {
		t.Fatal("Expected failure unmarshaling bad JSON input.")
	}
}

var testNet *BasicNet

func testAddNet(wl NetACL, ns string, t *testing.T) {
	_, n, err := net.ParseCIDR(ns)
	if err != nil {
		t.Fatalf("%v", err)
	}

	wl.Add(n)
}

func testDelNet(wl NetACL, ns string, t *testing.T) {
	_, n, err := net.ParseCIDR(ns)
	if err != nil {
		t.Fatalf("%v", err)
	}

	wl.Remove(n)
}

func TestAdd(t *testing.T) {
	// call this to make sure it doesn't panic, and to make sure
	// these code paths are executed.
	testNet = NewBasicNet()
	testNet.Add(nil)

	testAddNet(testNet, "192.168.3.0/24", t)
}

func TestRemove(t *testing.T) {
	testNet.Remove(nil)
	testDelNet(testNet, "192.168.1.1/32", t)
	testDelNet(testNet, "192.168.3.0/24", t)
}

func TestFailPermitted(t *testing.T) {
	var ip = []byte{0, 0}
	if testNet.Permitted(ip) {
		t.Fatal("Expected failure checking invalid IP address.")
	}
}
