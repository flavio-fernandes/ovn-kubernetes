package libovsdbops

import (
	"fmt"
	"net"
	"testing"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	libovsdbtest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
)

func TestUpdateNodeSwitchExcludeIPs(t *testing.T) {
	nodeName := "ovn-control-plane"

	fakeManagementPort := &nbdb.LogicalSwitchPort{
		Name: types.K8sPrefix + nodeName,
		UUID: types.K8sPrefix + nodeName + "-uuid",
	}

	fakeHoPort := &nbdb.LogicalSwitchPort{
		Name: types.HybridOverlayPrefix + nodeName,
		UUID: types.HybridOverlayPrefix + nodeName + "-uuid",
	}

	tests := []struct {
		desc                    string
		inpSubnetStr            string
		setCfgHybridOvlyEnabled bool
		initialNbdb             libovsdbtest.TestSetup
		expectedNbdb            libovsdbtest.TestSetup
	}{
		{
			desc: "IPv6 CIDR, never excludes",
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						Name:  nodeName,
						UUID:  nodeName + "-uuid",
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						Name:  nodeName,
						UUID:  nodeName + "-uuid",
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
			inpSubnetStr: "fd04:3e42:4a4e:3381::/64",
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=true, sets haveMangementPort=true, ovn-nbctl command excludeIPs list empty",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=true, sets haveMangementPort=true, ovn-nbctl command excludeIPs list empty leaves existing otherConfig alone",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
						OtherConfig: map[string]string{
							"exclude_ips": "192.168.1.3",
							"mac_only":    "false",
						},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeManagementPort.UUID, fakeHoPort.UUID},
						OtherConfig: map[string]string{
							"mac_only": "false",
						},
					},
					fakeManagementPort,
					fakeHoPort,
				},
			},
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=true, sets haveHybridOverlayPort=false, ovn-nbctl command excludeIPs list populated",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeManagementPort.UUID},
					},
					fakeManagementPort,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:        nodeName + "-uuid",
						Name:        nodeName,
						Ports:       []string{fakeManagementPort.UUID},
						OtherConfig: map[string]string{"exclude_ips": "192.168.1.3"},
					},
					fakeManagementPort,
				},
			},
		},
		{
			desc:         "IPv4 CIDR, haveMangementPort=false, ovn-nbctl command with excludeIPs list populated, returns error ",
			inpSubnetStr: "192.168.1.0/24",
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{fakeHoPort.UUID},
					},
					fakeHoPort,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:        nodeName + "-uuid",
						Name:        nodeName,
						Ports:       []string{fakeHoPort.UUID},
						OtherConfig: map[string]string{"exclude_ips": "192.168.1.2"},
					},
					fakeHoPort,
				},
			},
		},
		{
			desc:                    "IPv4 CIDR, config.HybridOverlayEnable=false, sets haveHybridOverlayPort=false and haveManagementPort=false ovn-nbctl command excludeIPs list populated",
			inpSubnetStr:            "192.168.1.0/24",
			setCfgHybridOvlyEnabled: true,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:  nodeName + "-uuid",
						Name:  nodeName,
						Ports: []string{},
					},
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						UUID:        nodeName + "-uuid",
						Name:        nodeName,
						Ports:       []string{},
						OtherConfig: map[string]string{"exclude_ips": "192.168.1.2..192.168.1.3"},
					},
				},
			},
		},
	}
	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d:%s", i, tc.desc), func(t *testing.T) {
			var fakeModelClient ModelClient
			stopChan := make(chan struct{})

			nbClient, _ := libovsdbtest.NewNBTestHarness(tc.initialNbdb, stopChan)
			fakeModelClient = NewModelClient(nbClient)

			_, ipnet, err := net.ParseCIDR(tc.inpSubnetStr)
			if err != nil {
				t.Fail()
			}
			var e error
			if tc.setCfgHybridOvlyEnabled {
				config.HybridOverlay.Enabled = true
				if e = UpdateNodeSwitchExcludeIPs(fakeModelClient, nodeName, ipnet); e != nil {
					t.Fatal(fmt.Errorf("failed to update NodeSwitchExcludeIPs with Hybrid Overlay enabled err: %v", e))
				}
				config.HybridOverlay.Enabled = false
			} else {
				if e = UpdateNodeSwitchExcludeIPs(fakeModelClient, nodeName, ipnet); e != nil {
					t.Fatal(fmt.Errorf("failed to update NodeSwitchExcludeIPs with Hybrid Overlay disabled err: %v", e))
				}

			}

			matcher := libovsdbtest.HaveDataIgnoringUUIDs(tc.expectedNbdb.NBData)
			success, err := matcher.Match(fakeModelClient.client)
			if !success {
				t.Fatal(fmt.Errorf("test: \"%s\" didn't match expected with actual, err: %v", tc.desc, matcher.FailureMessage(fakeModelClient.client)))
			}
			if err != nil {
				t.Fatal(fmt.Errorf("test: \"%s\" encountered error: %v", tc.desc, err))
			}

			close(stopChan)
		})
	}
}

func TestRemoveACLFromNodeSwitches(t *testing.T) {
	fakeACL := &nbdb.ACL{
		UUID: "a08ea426-2288-11eb-a30b-a8a1590cda29",
	}

	fakeSwitch1 := &nbdb.LogicalSwitch{
		Name: "sw1",
		//UUID: "sw1-uuid",
		ACLs: []string{fakeACL.UUID},
	}

	fakeSwitch2 := &nbdb.LogicalSwitch{
		Name: "sw2",
		//UUID: "sw2-uuid",
		ACLs: []string{fakeACL.UUID},
	}

	tests := []struct {
		desc         string
		aclUUID      string
		expectErr    bool
		initialNbdb  libovsdbtest.TestSetup
		expectedNbdb libovsdbtest.TestSetup
	}{
		{
			desc:      "remove acl on two switches",
			aclUUID:   "a08ea426-2288-11eb-a30b-a8a1590cda29",
			expectErr: false,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					fakeSwitch1,
					fakeSwitch2,
				},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{
					&nbdb.LogicalSwitch{
						Name: "sw1",
						UUID: "sw1-uuid",
					},
					&nbdb.LogicalSwitch{
						Name: "sw2",
						UUID: "sw2-uuid",
					},
				},
			},
		},
		{
			desc:      "remove acl on no switches",
			aclUUID:   "FAKE-UUID",
			expectErr: true,
			initialNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{},
			},
			expectedNbdb: libovsdbtest.TestSetup{
				NBData: []libovsdbtest.TestData{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			var fakeModelClient ModelClient
			stopChan := make(chan struct{})

			nbClient, _ := libovsdbtest.NewNBTestHarness(tt.initialNbdb, stopChan)
			fakeModelClient = NewModelClient(nbClient)

			fakeSwitches := []nbdb.LogicalSwitch{
				*fakeSwitch1,
				*fakeSwitch2,
			}

			err := RemoveACLFromSwitches(fakeModelClient, fakeSwitches, tt.aclUUID)
			if err != nil && !tt.expectErr {
				t.Fatal(fmt.Errorf("RemoveACLFromNodeSwitches() error = %v", err))
			}

			matcher := libovsdbtest.HaveDataIgnoringUUIDs(tt.expectedNbdb.NBData)
			success, err := matcher.Match(fakeModelClient.client)

			if !success {
				t.Fatal(fmt.Errorf("test: \"%s\" didn't match expected with actual, err: %v", tt.desc, matcher.FailureMessage(fakeModelClient.client)))
			}
			if err != nil {
				t.Fatal(fmt.Errorf("test: \"%s\" encountered error: %v", tt.desc, err))
			}

			close(stopChan)
		})
	}
}
