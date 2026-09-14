// Package iface provides cross-platform network interface enumeration and resolution
package iface

import (
	"fmt"
	"net"
	"strings"
)

// InterfaceInfo holds info about a system network interface
type InterfaceInfo struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	HardwareAddr string   `json:"hardware_addr"`
	IPs          []string `json:"ips"`
	Flags        string   `json:"flags"`
}

// GetAvailableInterfaces returns a list of active network interfaces with their IPs
func GetAvailableInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	var results []InterfaceInfo
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ips []string
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil {
				ips = append(ips, ip.String())
			}
		}

		results = append(results, InterfaceInfo{
			Index:        iface.Index,
			Name:         iface.Name,
			HardwareAddr: iface.HardwareAddr.String(),
			IPs:          ips,
			Flags:        iface.Flags.String(),
		})
	}

	return results, nil
}

// ResolveInterfaceIP resolves an interface name (e.g. "eth0", "Ethernet", "Wi-Fi", "1") or IP to a bindable IP address string.
// If input is empty, returns "" (bind all).
// If input is already a valid IP address, returns it as is.
func ResolveInterfaceIP(ifaceOrIP string) (string, error) {
	ifaceOrIP = strings.TrimSpace(ifaceOrIP)
	if ifaceOrIP == "" || ifaceOrIP == "0.0.0.0" || strings.EqualFold(ifaceOrIP, "all") {
		return "", nil
	}

	// Check if it's already a valid IP address
	if parsedIP := net.ParseIP(ifaceOrIP); parsedIP != nil {
		return parsedIP.String(), nil
	}

	// Query system interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w", err)
	}

	// 1. Try exact name match (case-insensitive)
	for _, iface := range ifaces {
		if strings.EqualFold(iface.Name, ifaceOrIP) {
			return getFirstValidIP(&iface)
		}
	}

	// 2. Try matching interface index number
	for _, iface := range ifaces {
		if fmt.Sprintf("%d", iface.Index) == ifaceOrIP {
			return getFirstValidIP(&iface)
		}
	}

	// 3. Partial/substring match for Windows interface names (e.g. "Ethernet" matching "Ethernet 2")
	for _, iface := range ifaces {
		if strings.Contains(strings.ToLower(iface.Name), strings.ToLower(ifaceOrIP)) {
			return getFirstValidIP(&iface)
		}
	}

	return "", fmt.Errorf("network interface or IP '%s' not found on system", ifaceOrIP)
}

// getFirstValidIP returns the first valid non-loopback IPv4 (or IPv6) address for an interface
func getFirstValidIP(iface *net.Interface) (string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for interface %s: %w", iface.Name, err)
	}

	var fallbackIP string

	// Prefer IPv4 address
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip == nil {
			continue
		}

		ip4 := ip.To4()
		if ip4 != nil {
			return ip4.String(), nil
		}

		if fallbackIP == "" {
			fallbackIP = ip.String()
		}
	}

	if fallbackIP != "" {
		return fallbackIP, nil
	}

	return "", fmt.Errorf("no valid IP address assigned to interface %s", iface.Name)
}
