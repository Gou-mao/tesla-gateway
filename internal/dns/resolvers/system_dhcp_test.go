package resolvers

import (
	"reflect"
	"testing"
)

func TestParseUbusDNSServers(t *testing.T) {
	tests := []struct {
		name       string
		document   string
		wantServer []string
		wantIface  string
	}{
		{
			name: "prefers interface with default route",
			document: `{
				"interface": [
					{
						"interface": "lan",
						"up": true,
						"dns-server": ["192.168.1.1"]
					},
					{
						"interface": "stawan",
						"up": true,
						"route": [
							{"target": "192.168.1.0", "netmask": "255.255.255.0"},
							{"target": "0.0.0.0", "netmask": "0.0.0.0"}
						],
						"dns-server": ["10.1.1.1", "2001:db8::53"]
					}
				]
			}`,
			wantServer: []string{"10.1.1.1", "2001:db8::53"},
			wantIface:  "stawan",
		},
		{
			name: "real openwrt dump with numeric route mask and table",
			document: `{"interface":[{"interface":"stawan","up":true,"proto":"dhcp",` +
				`"dns-server":["192.168.1.1"],` +
				`"route":[{"target":"0.0.0.0","netmask":"0.0.0.0","mask":0,"nexthop":"192.168.1.1","table":254}],` +
				`"ipv4-address":[{"address":"192.168.1.29","mask":24}]}]}`,
			wantServer: []string{"192.168.1.1"},
			wantIface:  "stawan",
		},
		{
			name: "mixed interfaces tolerate numeric and string field types",
			document: `{
				"interface": [
					{
						"interface": "down0",
						"up": false,
						"dns-server": ["10.255.255.1"],
						"route": [{"target": "0.0.0.0", "netmask": "0.0.0.0", "mask": 0, "table": 254}],
						"ipv4-address": [{"address": "10.0.0.2", "mask": 24}]
					},
					{
						"interface": "lan",
						"up": true,
						"dns-server": [],
						"route": [{"target": "192.168.9.0", "netmask": "255.255.255.0", "mask": 24, "table": 254}],
						"ipv4-address": [{"address": "192.168.9.1", "mask": 24}]
					},
					{
						"interface": "stawan",
						"up": true,
						"proto": "dhcp",
						"dns-server": ["192.168.1.1"],
						"route": [{
							"target": "0.0.0.0",
							"netmask": "0.0.0.0",
							"mask": "0",
							"nexthop": "192.168.1.1",
							"table": 254,
							"metric": 0,
							"mtu": 1500
						}],
						"ipv4-address": [{"address": "192.168.1.29", "mask": 24}],
						"uptime": 12345,
						"source": "dhcp"
					}
				]
			}`,
			wantServer: []string{"192.168.1.1"},
			wantIface:  "stawan",
		},
		{
			name: "default route uses target and netmask rather than numeric mask",
			document: `{
				"interface": [
					{
						"interface": "lan",
						"up": true,
						"dns-server": ["192.168.1.1"],
						"route": [{"target": "192.168.1.0", "netmask": "255.255.255.0", "mask": 0}]
					},
					{
						"interface": "wan",
						"up": true,
						"dns-server": ["10.1.1.1"],
						"route": [{"target": "0.0.0.0", "netmask": "0.0.0.0", "mask": 16}]
					}
				]
			}`,
			wantServer: []string{"10.1.1.1"},
			wantIface:  "wan",
		},
		{
			name: "falls back to first up interface without default route",
			document: `{
				"interface": [
					{"interface": "down", "up": false, "dns-server": ["1.1.1.1"]},
					{"interface": "modem", "up": true, "dns-server": ["10.2.2.2"]},
					{"interface": "wan", "up": true, "dns-server": ["10.3.3.3"]}
				]
			}`,
			wantServer: []string{"10.2.2.2"},
			wantIface:  "modem",
		},
		{
			name: "skips interfaces without dns-server",
			document: `{
				"interface": [
					{"interface": "empty", "up": true, "dns-server": []},
					{"interface": "lan", "up": true, "dns-server": ["192.168.1.1"]}
				]
			}`,
			wantServer: []string{"192.168.1.1"},
			wantIface:  "lan",
		},
		{
			name: "default route without dns does not win",
			document: `{
				"interface": [
					{
						"interface": "wan",
						"up": true,
						"route": [{"target": "0.0.0.0", "netmask": "0.0.0.0"}],
						"dns-server": []
					},
					{"interface": "lan", "up": true, "dns-server": ["192.168.1.1"]}
				]
			}`,
			wantServer: []string{"192.168.1.1"},
			wantIface:  "lan",
		},
		{
			name: "default route in cidr form",
			document: `{
				"interface": [
					{"interface": "wan", "up": true, "route": [{"target": "0.0.0.0/0"}], "dns-server": ["9.9.9.9"]}
				]
			}`,
			wantServer: []string{"9.9.9.9"},
			wantIface:  "wan",
		},
		{
			name: "default_route array is accepted",
			document: `{
				"interface": [
					{"interface": "wan", "up": true, "default_route": ["0.0.0.0/0"], "dns-server": ["9.9.9.9"]}
				]
			}`,
			wantServer: []string{"9.9.9.9"},
			wantIface:  "wan",
		},
		{
			name: "invalid and empty dns entries are skipped",
			document: `{
				"interface": [
					{"interface": "wan", "up": true, "dns-server": ["", "not-an-ip", "8.8.8.8"]}
				]
			}`,
			wantServer: []string{"8.8.8.8"},
			wantIface:  "wan",
		},
		{
			name: "scalar dns-server is accepted",
			document: `{
				"interface": [
					{"interface": "wan", "up": true, "dns-server": "8.8.4.4"}
				]
			}`,
			wantServer: []string{"8.8.4.4"},
			wantIface:  "wan",
		},
		{
			name:       "no eligible interface",
			document:   `{"interface": [{"interface": "lan", "up": false, "dns-server": ["1.1.1.1"]}]}`,
			wantServer: nil,
			wantIface:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			servers, iface, err := parseUbusDNSServers([]byte(tc.document))
			if err != nil {
				t.Fatalf("parseUbusDNSServers() = %v", err)
			}
			if !reflect.DeepEqual(servers, tc.wantServer) {
				t.Errorf("servers = %v, want %v", servers, tc.wantServer)
			}
			if iface != tc.wantIface {
				t.Errorf("interface = %q, want %q", iface, tc.wantIface)
			}
		})
	}
}

func TestParseUbusDNSServersRejectsMalformedJSON(t *testing.T) {
	if _, _, err := parseUbusDNSServers([]byte("{not-json")); err == nil {
		t.Fatal("parseUbusDNSServers() = nil error, want parse error")
	}
}
