package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/enboxorg/meshd/internal/dwn"
	dwncrypto "github.com/enboxorg/meshd/internal/dwn/crypto"
	"github.com/enboxorg/meshd/protocols"
)

const (
	materializerNetworkID = "network-record"
	materializerSelfDID   = "did:jwk:self"
	materializerPeerDID   = "did:jwk:peer"
)

func TestMaterializeRawMeshRecordSetProjectsCompleteMapState(t *testing.T) {
	records := []json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: "unknown-record", path: "network/invite", parentContext: materializerNetworkID,
			data: json.RawMessage(`not-json`), timestamp: "2026-07-11T12:00:20Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "foreign-node", protocol: "https://example.com/not-mesh", path: "network/node",
			parentContext: materializerNetworkID, recipient: "did:jwk:foreign",
			data: json.RawMessage(`not-json`), timestamp: "2026-07-11T12:00:21Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network",
			data:      NetworkConfig{Name: "production", MeshCIDR: "10.200.0.0/16", DNSServers: []string{"10.200.0.53"}, MagicDNSSuffix: "prod.mesh"},
			timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "member-record", path: "network/member", parentContext: materializerNetworkID,
			recipient: "did:jwk:member", data: MemberRecord{Label: "member", AddedAt: "2026-07-11T12:00:01Z"},
			timestamp: "2026-07-11T12:00:01Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID,
			data:      NodeRecord{MeshIP: "10.200.1.1", Label: "self-label", AddedAt: "2026-07-11T12:00:02Z"},
			timestamp: "2026-07-11T12:00:02Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-node", path: "network/member/node", parentContext: materializerNetworkID + "/member-record",
			recipient: materializerPeerDID,
			data:      NodeRecord{MeshIP: "10.200.1.2", Label: "peer-label", OwnerDID: "did:jwk:member", AddedAt: "2026-07-11T12:00:03Z"},
			timestamp: "2026-07-11T12:00:03Z",
		}),
		// This orphan is in the mesh protocol but outside the materialized
		// member dependency graph and must not enter the node map.
		materializerRecord(t, materializerRecordSpec{
			id: "orphan-node", path: "network/member/node", parentContext: materializerNetworkID + "/missing-member",
			recipient: "did:jwk:orphan", data: NodeRecord{MeshIP: "10.200.1.9"},
			timestamp: "2026-07-11T12:00:04Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "relay-record", path: "network/relay", parentContext: materializerNetworkID,
			data:      RelayData{URL: "relay.example.com", Region: "test", STUNPort: 3478},
			timestamp: "2026-07-11T12:00:05Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "acl-old", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data: ACLPolicyData{Version: 1, DefaultAction: "deny"}, timestamp: "2026-07-11T12:00:06Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "acl-new", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data:      ACLPolicyData{Version: 2, DefaultAction: "accept", Groups: map[string][]string{"all": {materializerSelfDID, materializerPeerDID}}},
			timestamp: "2026-07-11T12:00:07Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-info-old", path: "network/node/nodeInfo", parentContext: materializerNetworkID + "/self-node",
			data: NodeInfoData{Hostname: "old-self"}, timestamp: "2026-07-11T12:00:08Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-info-new", path: "network/node/nodeInfo", parentContext: materializerNetworkID + "/self-node",
			data:      NodeInfoData{Hostname: "self-host", OS: "darwin", Capabilities: []string{"ssh"}},
			timestamp: "2026-07-11T12:00:09Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-info", path: "network/member/node/nodeInfo", parentContext: materializerNetworkID + "/member-record/peer-node",
			data: NodeInfoData{Hostname: "peer-host", OS: "linux"}, timestamp: "2026-07-11T12:00:10Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data:      EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}, DiscoKey: "self-disco", UpdatedAt: "2026-07-11T12:00:11Z"},
			timestamp: "2026-07-11T12:00:11Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-endpoint", path: "network/member/node/endpoint", parentContext: materializerNetworkID + "/member-record/peer-node",
			data:      EndpointData{LocalEndpoints: []string{"192.0.2.2:2222"}, PreferredDERP: 7, DiscoKey: "peer-disco", UpdatedAt: "2026-07-11T12:00:12Z"},
			timestamp: "2026-07-11T12:00:12Z",
		}),
	}

	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatalf("newRawMeshRecordSet: %v", err)
	}
	client := newMaterializerTestClient()
	response, err := client.materializeRawMeshRecordSet(context.Background(), set)
	if err != nil {
		t.Fatalf("materializeRawMeshRecordSet: %v", err)
	}

	if response.Node == nil || response.Node.DID != materializerSelfDID || response.Node.Name != "self-host" {
		t.Fatalf("self node = %#v", response.Node)
	}
	if got := response.Node.Endpoints; len(got) != 1 || got[0] != "192.0.2.1:1111" {
		t.Fatalf("self endpoints = %#v", got)
	}
	if len(response.Peers) != 1 || response.Peers[0].DID != materializerPeerDID || response.Peers[0].Name != "peer-host" {
		t.Fatalf("peers = %#v", response.Peers)
	}
	if response.Peers[0].MemberRecordID != "member-record" || response.Peers[0].PreferredDERP != 7 {
		t.Fatalf("member peer projection = %#v", response.Peers[0])
	}
	if len(response.DERPMap.Regions) != 1 || response.DERPMap.Regions[1].Nodes[0].HostName != "relay.example.com" {
		t.Fatalf("DERP map = %#v", response.DERPMap)
	}
	if response.DNSConfig.MagicDNSSuffix != "prod.mesh" || len(response.PacketFilter) != 1 {
		t.Fatalf("DNS/filter = %#v / %#v", response.DNSConfig, response.PacketFilter)
	}
	if client.network == nil || client.network.Name != "production" || client.acl == nil || client.acl.Version != 2 {
		t.Fatalf("network/ACL = %#v / %#v", client.network, client.acl)
	}
	if member := client.members["did:jwk:member"]; member == nil || member.RecordID != "member-record" {
		t.Fatalf("member projection = %#v", member)
	}
	if _, ok := client.nodes["did:jwk:foreign"]; ok {
		t.Fatal("foreign-protocol node entered materialized state")
	}
	if _, ok := client.nodes["did:jwk:orphan"]; ok {
		t.Fatal("orphan member node entered materialized state")
	}
}

func TestMaterializeRawMeshRecordSetAppliesEndpointUpdateAndDelete(t *testing.T) {
	base := materializerBaseRecords(t)
	base = append(base, materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
		data:      EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}, UpdatedAt: "2026-07-11T12:00:02Z"},
		timestamp: "2026-07-11T12:00:02Z",
	}))
	set, err := newRawMeshRecordSet(base, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	firstNode := client.nodes[materializerSelfDID]
	if got := firstNode.Endpoints[0].LocalEndpoints[0]; got != "192.0.2.1:1111" {
		t.Fatalf("initial endpoint = %q", got)
	}

	updated := materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
		data:      EndpointData{LocalEndpoints: []string{"192.0.2.1:2222"}, UpdatedAt: "2026-07-11T12:00:03Z"},
		timestamp: "2026-07-11T12:00:03Z",
	})
	if changed, err := set.addEntries([]json.RawMessage{updated}, ""); err != nil || !changed {
		t.Fatalf("update raw set changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	secondNode := client.nodes[materializerSelfDID]
	if secondNode == firstNode {
		t.Fatal("endpoint update reused the prior node pointer")
	}
	if got := secondNode.Endpoints[0].LocalEndpoints[0]; got != "192.0.2.1:2222" {
		t.Fatalf("updated endpoint = %q", got)
	}
	if got := firstNode.Endpoints[0].LocalEndpoints[0]; got != "192.0.2.1:1111" {
		t.Fatalf("new projection mutated prior endpoint = %q", got)
	}

	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "self-endpoint", "2026-07-11T12:00:04Z"), "")
	if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
		t.Fatalf("delete raw record changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if got := len(client.nodes[materializerSelfDID].Endpoints); got != 0 {
		t.Fatalf("endpoints after delete = %d, want 0", got)
	}
}

func TestMaterializeRawMeshRecordSetRollbackAndDeepIsolation(t *testing.T) {
	client := newMaterializerTestClient()
	oldNetwork := &NetworkConfig{Name: "old", MeshCIDR: "10.199.0.0/16", DNSServers: []string{"old-dns"}}
	oldMember := &MemberRecord{DID: "did:jwk:old-member", Label: "old-member", RecordID: "old-member-record"}
	oldNode := &NodeRecord{
		DID: materializerSelfDID, MeshIP: "10.199.1.1", RecordID: "old-node",
		Endpoints: []EndpointData{{LocalEndpoints: []string{"old-endpoint"}}},
	}
	oldRelay := &RelayData{URL: "old-relay", Region: "old"}
	oldACL := &ACLPolicyData{Version: 99, Groups: map[string][]string{"old": {materializerSelfDID}}}
	client.network = oldNetwork
	client.members = map[string]*MemberRecord{oldMember.DID: oldMember}
	client.nodes = map[string]*NodeRecord{materializerSelfDID: oldNode}
	client.relays = []*RelayData{oldRelay}
	client.acl = oldACL
	client.endpointFailures = map[string]string{"old-endpoint": "key-unavailable"}

	badSet, err := newRawMeshRecordSet([]json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network", data: NetworkConfig{Name: "bad", MeshCIDR: "10.200.0.0/16"},
			timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-opaque", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.9"}, encrypted: true,
			timestamp: "2026-07-11T12:00:01Z",
		}),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(
		context.Background(), badSet, materializerUnavailableDecryptors("network/node"),
	); err == nil {
		t.Fatal("cold opaque self materialization succeeded")
	}
	assertMaterializerOldState(t, client, oldNetwork, oldMember, oldNode, oldRelay, oldACL)

	rateSet, err := newRawMeshRecordSet(append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "encrypted-peer", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2"}, encrypted: true,
			timestamp: "2026-07-11T12:00:02Z",
		}),
	), "")
	if err != nil {
		t.Fatal(err)
	}
	rateLimitDecryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/node" {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			return nil, fmt.Errorf("delivery lookup: %w", dwn.ErrRateLimited)
		}
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), rateSet, rateLimitDecryptors); !errors.Is(err, dwn.ErrRateLimited) {
		t.Fatalf("rate-limited materialization error = %v", err)
	}
	assertMaterializerOldState(t, client, oldNetwork, oldMember, oldNode, oldRelay, oldACL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.materializeRawMeshRecordSet(ctx, rateSet); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled materialization error = %v", err)
	}
	assertMaterializerOldState(t, client, oldNetwork, oldMember, oldNode, oldRelay, oldACL)

	goodSet, err := newRawMeshRecordSet(materializerBaseRecords(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.materializeRawMeshRecordSet(context.Background(), goodSet); err != nil {
		t.Fatal(err)
	}
	if client.network == oldNetwork || client.nodes[materializerSelfDID] == oldNode {
		t.Fatal("successful projection reused prior state pointers")
	}
	client.network.DNSServers[0] = "new-dns"
	client.nodes[materializerSelfDID].Endpoints = append(client.nodes[materializerSelfDID].Endpoints,
		EndpointData{LocalEndpoints: []string{"new-endpoint"}})
	if oldNetwork.DNSServers[0] != "old-dns" || oldNode.Endpoints[0].LocalEndpoints[0] != "old-endpoint" {
		t.Fatalf("successful projection aliased prior nested state: network=%#v node=%#v", oldNetwork, oldNode)
	}
}

func assertMaterializerOldState(
	t *testing.T,
	client *DWNClient,
	oldNetwork *NetworkConfig,
	oldMember *MemberRecord,
	oldNode *NodeRecord,
	oldRelay *RelayData,
	oldACL *ACLPolicyData,
) {
	t.Helper()
	if client.network != oldNetwork || client.members[oldMember.DID] != oldMember ||
		client.nodes[materializerSelfDID] != oldNode || len(client.relays) != 1 ||
		client.relays[0] != oldRelay || client.acl != oldACL {
		t.Fatalf("failed materialization replaced live state: network=%p member=%p node=%p relay=%p acl=%p",
			client.network, client.members[oldMember.DID], client.nodes[materializerSelfDID], client.relays[0], client.acl)
	}
	client.members["same-map-member"] = oldMember
	client.nodes["same-map-node"] = oldNode
	client.endpointFailures["same-map-failure"] = "parse"
	if client.members["same-map-member"] != oldMember || client.nodes["same-map-node"] != oldNode ||
		client.endpointFailures["same-map-failure"] != "parse" {
		t.Fatal("failed materialization replaced a live map")
	}
	delete(client.members, "same-map-member")
	delete(client.nodes, "same-map-node")
	delete(client.endpointFailures, "same-map-failure")
}

func materializerBaseRecords(t *testing.T) []json.RawMessage {
	t.Helper()
	return []json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network",
			data:      NetworkConfig{Name: "base", MeshCIDR: "10.200.0.0/16", DNSServers: []string{"10.200.0.53"}},
			timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID,
			data:      NodeRecord{MeshIP: "10.200.1.1", Label: "self", AddedAt: "2026-07-11T12:00:01Z"},
			timestamp: "2026-07-11T12:00:01Z",
		}),
	}
}

func TestMaterializeRawMeshRecordSetUsesNewestEndpointSnapshot(t *testing.T) {
	records := append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "self-endpoint-old", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data: EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}}, timestamp: "2026-07-11T12:00:02Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-endpoint-new", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data: EndpointData{LocalEndpoints: []string{"192.0.2.1:2222"}}, timestamp: "2026-07-11T12:00:03Z",
		}),
	)
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	endpoints := client.nodes[materializerSelfDID].Endpoints
	if len(endpoints) != 1 || len(endpoints[0].LocalEndpoints) != 1 || endpoints[0].LocalEndpoints[0] != "192.0.2.1:2222" {
		t.Fatalf("materialized endpoints = %#v, want only newest snapshot", endpoints)
	}
}

func TestMaterializeRawMeshRecordSetACLDeleteClearsLastPolicy(t *testing.T) {
	records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "acl-record", path: "network/aclPolicy", parentContext: materializerNetworkID,
		data: ACLPolicyData{Version: 1, DefaultAction: "deny"}, timestamp: "2026-07-11T12:00:02Z",
	}))
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if client.acl == nil || client.acl.Version != 1 {
		t.Fatalf("initial ACL = %#v", client.acl)
	}
	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "acl-record", "2026-07-11T12:00:03Z"), "")
	if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
		t.Fatalf("delete ACL changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if client.acl != nil {
		t.Fatalf("deleted ACL remained active: %#v", client.acl)
	}
}

func TestMaterializeRawMeshRecordSetRelayLastGoodPolicy(t *testing.T) {
	invalidRelay := materializerRecord(t, materializerRecordSpec{
		id: "relay-record", path: "network/relay", parentContext: materializerNetworkID,
		data: json.RawMessage("not-json"), dateCreated: "2026-07-11T12:00:02Z", timestamp: "2026-07-11T12:01:00Z",
	})
	t.Run("cold unreadable fails", func(t *testing.T) {
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), invalidRelay), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err == nil {
			t.Fatal("cold unreadable relay unexpectedly projected public defaults")
		}
	})

	t.Run("warm unreadable preserves and delete removes", func(t *testing.T) {
		validRelay := materializerRecord(t, materializerRecordSpec{
			id: "relay-record", path: "network/relay", parentContext: materializerNetworkID,
			data:        RelayData{URL: "last-good.example.com", Region: "private"},
			dateCreated: "2026-07-11T12:00:02Z", timestamp: "2026-07-11T12:00:02Z",
		})
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), validRelay), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(invalidRelay, ""), ""); err != nil || !changed {
			t.Fatalf("relay replacement changed=%v err=%v", changed, err)
		}
		response, err := client.materializeRawMeshRecordSet(context.Background(), set)
		if err != nil {
			t.Fatalf("warm unreadable relay: %v", err)
		}
		if len(client.relays) != 1 || client.relays[0].URL != "last-good.example.com" || len(response.DERPMap.Regions) != 1 {
			t.Fatalf("warm relay projection = %#v DERP=%#v", client.relays, response.DERPMap)
		}

		deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "relay-record", "2026-07-11T12:02:00Z"), "")
		if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
			t.Fatalf("delete relay changed=%v err=%v", changed, err)
		}
		response, err = client.materializeRawMeshRecordSet(context.Background(), set)
		if err != nil {
			t.Fatal(err)
		}
		if len(client.relays) != 0 {
			t.Fatalf("deleted relay remained active: %#v", client.relays)
		}
		for _, region := range response.DERPMap.Regions {
			for _, node := range region.Nodes {
				if node.HostName == "last-good.example.com" {
					t.Fatalf("deleted custom relay remained in DERP map: %#v", response.DERPMap)
				}
			}
		}
	})
}

func TestMaterializeRawMeshRecordSetRelayOrderUsesDateCreated(t *testing.T) {
	records := append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "relay-created-first", path: "network/relay", parentContext: materializerNetworkID,
			data:        RelayData{URL: "first.example.com", Region: "first"},
			dateCreated: "2026-07-11T12:00:00Z", timestamp: "2026-07-11T12:10:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "relay-created-second", path: "network/relay", parentContext: materializerNetworkID,
			data:        RelayData{URL: "second.example.com", Region: "second"},
			dateCreated: "2026-07-11T12:01:00Z", timestamp: "2026-07-11T12:01:00Z",
		}),
	)
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	response, err := client.materializeRawMeshRecordSet(context.Background(), set)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.relays) != 2 || client.relays[0].URL != "first.example.com" || client.relays[1].URL != "second.example.com" {
		t.Fatalf("relay order = %#v", client.relays)
	}
	if response.DERPMap.Regions[1].Nodes[0].HostName != "first.example.com" || response.DERPMap.Regions[2].Nodes[0].HostName != "second.example.com" {
		t.Fatalf("DERP region order = %#v", response.DERPMap.Regions)
	}
}

func TestMaterializeRawMeshRecordSetUnreadableACLRetainsDeepClone(t *testing.T) {
	set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "acl-replacement", path: "network/aclPolicy", parentContext: materializerNetworkID, encrypted: true,
		data: ACLPolicyData{Version: 2, DefaultAction: "accept"}, timestamp: "2026-07-11T12:00:02Z",
	})), "")
	if err != nil {
		t.Fatal(err)
	}
	old := &ACLPolicyData{
		Version: 1, DefaultAction: "deny",
		Groups: map[string][]string{"operators": {"did:jwk:operator"}},
		Rules: []ACLRule{{
			Action: "accept", Src: []string{"did:jwk:operator"}, Dst: []string{materializerSelfDID},
			SrcPorts: []string{"1024-65535"}, DstPorts: []string{"22"},
		}},
	}
	client := newMaterializerTestClient()
	client.acl = old
	decryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/aclPolicy" {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			return nil, fmt.Errorf("%w: role audience key unavailable", errAudienceKeyDeliveryAbsent)
		}
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if client.acl == nil || client.acl == old || client.acl.Version != old.Version {
		t.Fatalf("retained ACL = %#v, old=%p retained=%p", client.acl, old, client.acl)
	}
	client.acl.Groups["operators"][0] = "did:jwk:mutated"
	client.acl.Rules[0].Src[0] = "did:jwk:mutated"
	client.acl.Rules[0].Dst[0] = "did:jwk:mutated"
	client.acl.Rules[0].SrcPorts[0] = "1"
	client.acl.Rules[0].DstPorts[0] = "1"
	if old.Groups["operators"][0] != "did:jwk:operator" || old.Rules[0].Src[0] != "did:jwk:operator" ||
		old.Rules[0].Dst[0] != materializerSelfDID || old.Rules[0].SrcPorts[0] != "1024-65535" || old.Rules[0].DstPorts[0] != "22" {
		t.Fatalf("retained ACL aliases last-good policy: %#v", old)
	}
}

func TestMaterializeRawMeshRecordSetColdUnreadableACLRejectsAtomically(t *testing.T) {
	tests := []struct {
		name      string
		data      any
		encrypted bool
	}{
		{name: "missing audience key", data: ACLPolicyData{Version: 2}, encrypted: true},
		{name: "malformed payload", data: json.RawMessage(`not-json`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
				id: "acl-cold", path: "network/aclPolicy", parentContext: materializerNetworkID,
				data: test.data, encrypted: test.encrypted, timestamp: "2026-07-11T12:00:02Z",
			})), "")
			if err != nil {
				t.Fatal(err)
			}
			client := newMaterializerTestClient()
			decryptors := func(_ context.Context, path string) EntryDecryptor {
				if !test.encrypted || path != "network/aclPolicy" {
					return nil
				}
				return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
					return nil, fmt.Errorf("%w: role audience key unavailable", errAudienceKeyDeliveryAbsent)
				}
			}
			if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err == nil {
				t.Fatal("cold unreadable ACL installed a map")
			}
			if client.network != nil || client.acl != nil || len(client.rawParsedOutcomes) != 0 {
				t.Fatalf("failed ACL projection mutated state: network=%#v acl=%#v cache=%d",
					client.network, client.acl, len(client.rawParsedOutcomes))
			}
		})
	}
}

func TestMaterializeRawMeshRecordSetKeyUnavailableSnapshotKeepsLastGoodUntilInvalidated(t *testing.T) {
	set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "endpoint-old", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
		data: EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}}, timestamp: "2026-07-11T12:00:02Z",
	})), "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}

	replacement := materializerRecord(t, materializerRecordSpec{
		id: "endpoint-new", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
		data: EndpointData{LocalEndpoints: []string{"192.0.2.1:2222"}}, encrypted: true, squash: true,
		timestamp: "2026-07-11T12:00:03Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
		t.Fatalf("replacement changed=%v err=%v", changed, err)
	}
	available := false
	decryptCalls := 0
	decryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/node/endpoint" {
			return nil
		}
		return func(ciphertext []byte, _ *dwncrypto.Encryption) ([]byte, error) {
			decryptCalls++
			if !available {
				return nil, fmt.Errorf("%w: delivery not present", errAudienceKeyDeliveryAbsent)
			}
			return ciphertext, nil
		}
	}
	for range 2 {
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
			t.Fatal(err)
		}
		endpoints := client.nodes[materializerSelfDID].Endpoints
		if len(endpoints) != 1 || endpoints[0].LocalEndpoints[0] != "192.0.2.1:1111" {
			t.Fatalf("key-unavailable snapshot replaced last-good: %#v", endpoints)
		}
	}
	if decryptCalls != 1 {
		t.Fatalf("cached opaque replacement decrypt calls = %d, want 1", decryptCalls)
	}

	cachedCount := len(client.rawParsedOutcomes)
	var opaqueKeys []rawParsedOutcomeKey
	for key, outcome := range client.rawParsedOutcomes {
		if outcome.opaque {
			opaqueKeys = append(opaqueKeys, key)
		}
	}
	client.invalidateRawParsedOutcomes()
	if len(client.rawParsedOutcomes) != cachedCount {
		t.Fatalf("generation invalidation cache size = %d, want %d", len(client.rawParsedOutcomes), cachedCount)
	}
	for _, key := range opaqueKeys {
		if _, ok := client.rawParsedOutcomes[key]; !ok {
			t.Fatalf("generation invalidation discarded opaque prior outcome %#v", key)
		}
	}
	failing := set.clone()
	if _, err := failing.addEntries([]json.RawMessage{materializerRecord(t, materializerRecordSpec{
		id: "acl-unreadable", path: "network/aclPolicy", parentContext: materializerNetworkID,
		data: json.RawMessage(`not-json`), timestamp: "2026-07-11T12:00:04Z",
	})}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), failing, decryptors); err == nil {
		t.Fatal("failed projection with cold unreadable ACL succeeded")
	}
	for _, key := range opaqueKeys {
		if _, ok := client.rawParsedOutcomes[key]; !ok {
			t.Fatalf("failed projection discarded prior outcome %#v", key)
		}
	}

	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	endpoints := client.nodes[materializerSelfDID].Endpoints
	if decryptCalls != 2 || len(endpoints) != 1 || endpoints[0].LocalEndpoints[0] != "192.0.2.1:1111" {
		t.Fatalf("opaque retry lost last-good: calls=%d endpoints=%#v", decryptCalls, endpoints)
	}

	available = true
	client.invalidateRawParsedOutcomes()
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	endpoints = client.nodes[materializerSelfDID].Endpoints
	if decryptCalls != 3 || len(endpoints) != 1 || endpoints[0].LocalEndpoints[0] != "192.0.2.1:2222" {
		t.Fatalf("delivery invalidation did not install replacement: calls=%d endpoints=%#v", decryptCalls, endpoints)
	}
	client.invalidateRawParsedOutcomes()
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if decryptCalls != 3 {
		t.Fatalf("healthy anti-entropy invalidation re-decrypted successful outcome: calls=%d", decryptCalls)
	}
}

func TestMaterializeRawMeshRecordSetMemberAndNodeKeepLastGoodForNewerCID(t *testing.T) {
	records := append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "member-record", path: "network/member", parentContext: materializerNetworkID,
			recipient: "did:jwk:member", data: MemberRecord{Label: "last-good-member"},
			timestamp: "2026-07-11T12:00:02Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-node", path: "network/member/node", parentContext: materializerNetworkID + "/member-record",
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2", Label: "last-good-node"},
			timestamp: "2026-07-11T12:00:03Z",
		}),
	)
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}

	memberReplacement := materializerRecord(t, materializerRecordSpec{
		id: "member-record", path: "network/member", parentContext: materializerNetworkID,
		recipient: "did:jwk:member", data: MemberRecord{Label: "unreadable-member"}, encrypted: true,
		dateCreated: "2026-07-11T12:00:02Z", timestamp: "2026-07-11T12:00:04Z",
	})
	nodeReplacement := materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/member/node", parentContext: materializerNetworkID + "/member-record",
		recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.3", Label: "unreadable-node"}, encrypted: true,
		dateCreated: "2026-07-11T12:00:03Z", timestamp: "2026-07-11T12:00:05Z",
	})
	for _, replacement := range []json.RawMessage{memberReplacement, nodeReplacement} {
		if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
			t.Fatalf("apply replacement changed=%v err=%v", changed, err)
		}
	}
	decryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/member" && path != "network/member/node" {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			return nil, fmt.Errorf("%w: delivery not present", errAudienceKeyDeliveryAbsent)
		}
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if member := client.members["did:jwk:member"]; member == nil || member.Label != "last-good-member" {
		t.Fatalf("newer unreadable member replaced last-good: %#v", member)
	}
	if node := client.nodes[materializerPeerDID]; node == nil || node.MeshIP != "10.200.1.2" || node.Label != "last-good-node" {
		t.Fatalf("newer unreadable node replaced last-good: %#v", node)
	}

	for _, recordID := range []string{"peer-node", "member-record"} {
		deleted := rawRecordTestSubscription(rawRecordTestDelete(t, recordID, "2026-07-11T12:00:06Z"), "")
		if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
			t.Fatalf("delete %s changed=%v err=%v", recordID, changed, err)
		}
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.members["did:jwk:member"]; ok {
		t.Fatalf("deleted member remained active: %#v", client.members)
	}
	if _, ok := client.nodes[materializerPeerDID]; ok {
		t.Fatalf("deleted peer node remained active: %#v", client.nodes)
	}
}

func TestMaterializeRawMeshRecordSetNewIDNonSquashUsesStagedRecipientContribution(t *testing.T) {
	const (
		memberDID = "did:jwk:replacement-member"
		ownerDID  = "did:jwk:owner-peer"
	)
	records := append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "member-old", path: "network/member", parentContext: materializerNetworkID,
			recipient: memberDID, data: MemberRecord{Label: "last-good-member"},
			timestamp: "2026-07-11T12:00:02Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "member-new", path: "network/member", parentContext: materializerNetworkID,
			recipient: memberDID, data: MemberRecord{Label: "unreadable-member"}, encrypted: true,
			timestamp: "2026-07-11T12:00:03Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "member-child", path: "network/member/node", parentContext: materializerNetworkID + "/member-new",
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2", Label: "member-child"},
			timestamp: "2026-07-11T12:00:04Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "owner-old", path: "network/node", parentContext: materializerNetworkID,
			recipient: ownerDID, data: NodeRecord{MeshIP: "10.200.1.3", Label: "last-good-owner"},
			timestamp: "2026-07-11T12:00:02.100Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "owner-new", path: "network/node", parentContext: materializerNetworkID,
			recipient: ownerDID, data: NodeRecord{MeshIP: "10.200.1.30", Label: "unreadable-owner"}, encrypted: true,
			timestamp: "2026-07-11T12:00:03.100Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "owner-new-info", path: "network/node/nodeInfo", parentContext: materializerNetworkID + "/owner-new",
			data: NodeInfoData{Hostname: "owner-new-host"}, timestamp: "2026-07-11T12:00:04.100Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "owner-new-endpoint", path: "network/node/endpoint", parentContext: materializerNetworkID + "/owner-new",
			data: EndpointData{LocalEndpoints: []string{"192.0.2.30:3030"}}, timestamp: "2026-07-11T12:00:04.200Z",
		}),
	)
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(
		context.Background(), set, materializerUnavailableDecryptors("network/member", "network/node"),
	); err != nil {
		t.Fatal(err)
	}

	member := client.members[memberDID]
	if member == nil || member.Label != "last-good-member" || member.RecordID != "member-new" {
		t.Fatalf("staged member replacement = %#v", member)
	}
	memberChild := client.nodes[materializerPeerDID]
	if memberChild == nil || memberChild.MemberRecordID != "member-new" || memberChild.Label != "member-child" {
		t.Fatalf("child under replacement member = %#v", memberChild)
	}
	owner := client.nodes[ownerDID]
	if owner == nil || owner.MeshIP != "10.200.1.3" || owner.Label != "last-good-owner" || owner.RecordID != "owner-new" {
		t.Fatalf("staged owner-node replacement = %#v", owner)
	}
	if owner.Info == nil || owner.Info.Hostname != "owner-new-host" || len(owner.Endpoints) != 1 ||
		owner.Endpoints[0].LocalEndpoints[0] != "192.0.2.30:3030" {
		t.Fatalf("children did not attach to replacement owner node: %#v", owner)
	}
}

func TestMaterializeRawMeshRecordSetNewIDSquashUsesPriorRecipientContribution(t *testing.T) {
	t.Run("member", func(t *testing.T) {
		const memberDID = "did:jwk:squashed-member"
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
			id: "member-old", path: "network/member", parentContext: materializerNetworkID,
			recipient: memberDID, data: MemberRecord{Label: "last-good-member"}, timestamp: "2026-07-11T12:00:02Z",
		})), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		replacement := materializerRecord(t, materializerRecordSpec{
			id: "member-new", path: "network/member", parentContext: materializerNetworkID,
			recipient: memberDID, data: MemberRecord{Label: "unreadable"}, encrypted: true, squash: true,
			timestamp: "2026-07-11T12:00:03Z",
		})
		child := materializerRecord(t, materializerRecordSpec{
			id: "child-new", path: "network/member/node", parentContext: materializerNetworkID + "/member-new",
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.4", Label: "new-parent-child"},
			timestamp: "2026-07-11T12:00:04Z",
		})
		for _, raw := range []json.RawMessage{replacement, child} {
			if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(raw, ""), ""); err != nil || !changed {
				t.Fatalf("apply replacement changed=%v err=%v", changed, err)
			}
		}
		if _, ok := set.get("member-old"); ok {
			t.Fatal("member squash retained old raw record")
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member"),
		); err != nil {
			t.Fatal(err)
		}
		member := client.members[memberDID]
		if member == nil || member.Label != "last-good-member" || member.RecordID != "member-new" {
			t.Fatalf("squashed member replacement = %#v", member)
		}
		if node := client.nodes[materializerPeerDID]; node == nil || node.MemberRecordID != "member-new" || node.Label != "new-parent-child" {
			t.Fatalf("replacement member child = %#v", node)
		}
		deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "member-new", "2026-07-11T12:00:05Z"), "")
		if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
			t.Fatalf("delete replacement member changed=%v err=%v", changed, err)
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member"),
		); err != nil {
			t.Fatal(err)
		}
		if _, ok := client.members[memberDID]; ok {
			t.Fatalf("deleted replacement member remained: %#v", client.members)
		}
		if _, ok := client.nodes[materializerPeerDID]; ok {
			t.Fatalf("orphaned replacement child remained: %#v", client.nodes)
		}
	})

	t.Run("member node", func(t *testing.T) {
		const memberDID = "did:jwk:node-parent"
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t),
			materializerRecord(t, materializerRecordSpec{
				id: "member-parent", path: "network/member", parentContext: materializerNetworkID,
				recipient: memberDID, data: MemberRecord{Label: "parent"}, timestamp: "2026-07-11T12:00:02Z",
			}),
			materializerRecord(t, materializerRecordSpec{
				id: "node-old", path: "network/member/node", parentContext: materializerNetworkID + "/member-parent",
				recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.5", Label: "last-good-node"},
				timestamp: "2026-07-11T12:00:03Z",
			}),
		), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		replacement := materializerRecord(t, materializerRecordSpec{
			id: "node-new", path: "network/member/node", parentContext: materializerNetworkID + "/member-parent",
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.50", Label: "unreadable"},
			encrypted: true, squash: true, timestamp: "2026-07-11T12:00:04Z",
		})
		info := materializerRecord(t, materializerRecordSpec{
			id: "node-new-info", path: "network/member/node/nodeInfo",
			parentContext: materializerNetworkID + "/member-parent/node-new",
			data:          NodeInfoData{Hostname: "node-new-host"}, timestamp: "2026-07-11T12:00:05Z",
		})
		endpoint := materializerRecord(t, materializerRecordSpec{
			id: "node-new-endpoint", path: "network/member/node/endpoint",
			parentContext: materializerNetworkID + "/member-parent/node-new",
			data:          EndpointData{LocalEndpoints: []string{"192.0.2.50:5050"}}, timestamp: "2026-07-11T12:00:05.100Z",
		})
		for _, raw := range []json.RawMessage{replacement, info, endpoint} {
			if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(raw, ""), ""); err != nil || !changed {
				t.Fatalf("apply node replacement changed=%v err=%v", changed, err)
			}
		}
		if _, ok := set.get("node-old"); ok {
			t.Fatal("node squash retained old raw record")
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member/node"),
		); err != nil {
			t.Fatal(err)
		}
		node := client.nodes[materializerPeerDID]
		if node == nil || node.MeshIP != "10.200.1.5" || node.Label != "last-good-node" ||
			node.RecordID != "node-new" || node.MemberRecordID != "member-parent" {
			t.Fatalf("squashed member-node replacement = %#v", node)
		}
		if node.Info == nil || node.Info.Hostname != "node-new-host" || len(node.Endpoints) != 1 ||
			node.Endpoints[0].LocalEndpoints[0] != "192.0.2.50:5050" {
			t.Fatalf("children did not attach to replacement member node: %#v", node)
		}
		deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "node-new", "2026-07-11T12:00:06Z"), "")
		if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
			t.Fatalf("delete replacement node changed=%v err=%v", changed, err)
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member/node"),
		); err != nil {
			t.Fatal(err)
		}
		if _, ok := client.nodes[materializerPeerDID]; ok {
			t.Fatalf("deleted replacement node remained: %#v", client.nodes)
		}
	})
}

func TestMaterializeRawMeshRecordSetNewIDNeverInheritsAcrossRecipients(t *testing.T) {
	t.Run("member squash", func(t *testing.T) {
		const oldDID, newDID = "did:jwk:old-member", "did:jwk:new-member"
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
			id: "member-old", path: "network/member", parentContext: materializerNetworkID,
			recipient: oldDID, data: MemberRecord{Label: "must-not-leak"}, timestamp: "2026-07-11T12:00:02Z",
		})), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		replacement := materializerRecord(t, materializerRecordSpec{
			id: "member-new", path: "network/member", parentContext: materializerNetworkID,
			recipient: newDID, data: MemberRecord{Label: "unreadable"}, encrypted: true, squash: true,
			timestamp: "2026-07-11T12:00:03Z",
		})
		if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
			t.Fatalf("apply member replacement changed=%v err=%v", changed, err)
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member"),
		); err != nil {
			t.Fatal(err)
		}
		if _, ok := client.members[oldDID]; ok {
			t.Fatalf("squashed old recipient remained: %#v", client.members)
		}
		member := client.members[newDID]
		if member == nil || member.RecordID != "member-new" || member.Label != "" {
			t.Fatalf("new recipient inherited old member data: %#v", member)
		}
	})

	t.Run("owner node non-squash", func(t *testing.T) {
		const oldDID, newDID = "did:jwk:old-owner-node", "did:jwk:new-owner-node"
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t),
			materializerRecord(t, materializerRecordSpec{
				id: "owner-old", path: "network/node", parentContext: materializerNetworkID,
				recipient: oldDID, data: NodeRecord{MeshIP: "10.200.1.6", Label: "must-not-leak"},
				timestamp: "2026-07-11T12:00:02Z",
			}),
			materializerRecord(t, materializerRecordSpec{
				id: "owner-new", path: "network/node", parentContext: materializerNetworkID,
				recipient: newDID, data: NodeRecord{MeshIP: "10.200.1.60", Label: "unreadable"}, encrypted: true,
				timestamp: "2026-07-11T12:00:03Z",
			}),
		), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/node"),
		); err != nil {
			t.Fatal(err)
		}
		if old := client.nodes[oldDID]; old == nil || old.MeshIP != "10.200.1.6" || old.Label != "must-not-leak" {
			t.Fatalf("old recipient contribution = %#v", old)
		}
		fresh := client.nodes[newDID]
		if fresh == nil || fresh.RecordID != "owner-new" || fresh.MeshIP != "" || fresh.Label != "" {
			t.Fatalf("new recipient inherited old owner-node data: %#v", fresh)
		}
	})

	t.Run("member node squash", func(t *testing.T) {
		const oldDID, newDID = "did:jwk:old-member-node", "did:jwk:new-member-node"
		set, err := newRawMeshRecordSet(append(materializerBaseRecords(t),
			materializerRecord(t, materializerRecordSpec{
				id: "member-parent", path: "network/member", parentContext: materializerNetworkID,
				recipient: "did:jwk:parent", data: MemberRecord{Label: "parent"}, timestamp: "2026-07-11T12:00:02Z",
			}),
			materializerRecord(t, materializerRecordSpec{
				id: "node-old", path: "network/member/node", parentContext: materializerNetworkID + "/member-parent",
				recipient: oldDID, data: NodeRecord{MeshIP: "10.200.1.7", Label: "must-not-leak"},
				timestamp: "2026-07-11T12:00:03Z",
			}),
		), "")
		if err != nil {
			t.Fatal(err)
		}
		client := newMaterializerTestClient()
		if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
			t.Fatal(err)
		}
		replacement := materializerRecord(t, materializerRecordSpec{
			id: "node-new", path: "network/member/node", parentContext: materializerNetworkID + "/member-parent",
			recipient: newDID, data: NodeRecord{MeshIP: "10.200.1.70", Label: "unreadable"},
			encrypted: true, squash: true, timestamp: "2026-07-11T12:00:04Z",
		})
		if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
			t.Fatalf("apply member-node replacement changed=%v err=%v", changed, err)
		}
		if _, err := client.materializeRawMeshRecordSetWithDecryptors(
			context.Background(), set, materializerUnavailableDecryptors("network/member/node"),
		); err != nil {
			t.Fatal(err)
		}
		if _, ok := client.nodes[oldDID]; ok {
			t.Fatalf("squashed old node recipient remained: %#v", client.nodes)
		}
		fresh := client.nodes[newDID]
		if fresh == nil || fresh.RecordID != "node-new" || fresh.MemberRecordID != "member-parent" ||
			fresh.MeshIP != "" || fresh.Label != "" {
			t.Fatalf("new recipient inherited old member-node data: %#v", fresh)
		}
	})
}

func TestMaterializeRawMeshRecordSetNodeInfoSquashKeepsLastGoodUntilDelete(t *testing.T) {
	records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "node-info-old", path: "network/node/nodeInfo", parentContext: materializerNetworkID + "/self-node",
		data: NodeInfoData{Hostname: "last-good-host"}, timestamp: "2026-07-11T12:00:02Z",
	}))
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}

	replacement := materializerRecord(t, materializerRecordSpec{
		id: "node-info-new", path: "network/node/nodeInfo", parentContext: materializerNetworkID + "/self-node",
		data: NodeInfoData{Hostname: "unreadable-host"}, encrypted: true, squash: true,
		timestamp: "2026-07-11T12:00:03Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
		t.Fatalf("nodeInfo squash changed=%v err=%v", changed, err)
	}
	if _, ok := set.get("node-info-old"); ok {
		t.Fatal("squashed nodeInfo sibling remained in the raw set")
	}
	decryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/node/nodeInfo" {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			return nil, fmt.Errorf("%w: delivery not present", errAudienceKeyDeliveryAbsent)
		}
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if info := client.nodes[materializerSelfDID].Info; info == nil || info.Hostname != "last-good-host" {
		t.Fatalf("new-ID same-parent nodeInfo squash replaced last-good: %#v", info)
	}

	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "node-info-new", "2026-07-11T12:00:04Z"), "")
	if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
		t.Fatalf("delete nodeInfo changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatal(err)
	}
	if info := client.nodes[materializerSelfDID].Info; info != nil {
		t.Fatalf("deleted nodeInfo remained active: %#v", info)
	}
}

func TestMaterializeRawMeshRecordSetColdOpaqueSelfFailsClosed(t *testing.T) {
	network := materializerRecord(t, materializerRecordSpec{
		id: materializerNetworkID, path: "network",
		data: NetworkConfig{Name: "security", MeshCIDR: "10.200.0.0/16"}, timestamp: "2026-07-11T12:00:00Z",
	})
	tests := []struct {
		name    string
		records []json.RawMessage
	}{
		{
			name: "no prior node",
			records: []json.RawMessage{network, materializerRecord(t, materializerRecordSpec{
				id: "self-opaque", path: "network/node", parentContext: materializerNetworkID,
				recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"}, encrypted: true,
				timestamp: "2026-07-11T12:00:02Z",
			})},
		},
		{
			name: "different recipient is not prior",
			records: []json.RawMessage{
				network,
				materializerRecord(t, materializerRecordSpec{
					id: "other-readable", path: "network/node", parentContext: materializerNetworkID,
					recipient: "did:jwk:different-recipient", data: NodeRecord{MeshIP: "10.200.1.2", ExpiresAt: "2099-01-01T00:00:00Z"},
					timestamp: "2026-07-11T12:00:01Z",
				}),
				materializerRecord(t, materializerRecordSpec{
					id: "self-opaque", path: "network/node", parentContext: materializerNetworkID,
					recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"}, encrypted: true,
					timestamp: "2026-07-11T12:00:02Z",
				}),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set, err := newRawMeshRecordSet(test.records, "")
			if err != nil {
				t.Fatal(err)
			}
			client := newMaterializerTestClient()
			if _, err := client.materializeRawMeshRecordSetWithDecryptors(
				context.Background(), set, materializerUnavailableDecryptors("network/node"),
			); err == nil || !strings.Contains(err.Error(), "self node") || !strings.Contains(err.Error(), "last-good") {
				t.Fatalf("cold opaque self error = %v", err)
			}
			if client.network != nil || len(client.nodes) != 0 || len(client.rawParsedOutcomes) != 0 {
				t.Fatalf("failed self projection mutated state: network=%#v nodes=%#v cache=%d",
					client.network, client.nodes, len(client.rawParsedOutcomes))
			}
		})
	}
}

func TestMaterializeRawMeshRecordSetWarmOpaqueSelfPreservesExpiryThenDeleteDownAndRenew(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(time.Hour).Format(time.RFC3339Nano)
	renewedExpiry := now.Add(2 * time.Hour).Format(time.RFC3339Nano)
	records := []json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network",
			data: NetworkConfig{Name: "security", MeshCIDR: "10.200.0.0/16"}, timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID,
			data:      NodeRecord{MeshIP: "10.200.1.1", Label: "last-good-self", ExpiresAt: expiresAt},
			timestamp: "2026-07-11T12:00:01Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2", Label: "peer"},
			timestamp: "2026-07-11T12:00:02Z",
		}),
	}
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}

	replacement := materializerRecord(t, materializerRecordSpec{
		id: "self-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerSelfDID,
		data:      NodeRecord{MeshIP: "10.200.99.99", Label: "unreadable", ExpiresAt: ""}, encrypted: true,
		dateCreated: "2026-07-11T12:00:01Z", timestamp: "2026-07-11T12:00:03Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(replacement, ""), ""); err != nil || !changed {
		t.Fatalf("apply opaque self replacement changed=%v err=%v", changed, err)
	}
	response, err := client.materializeRawMeshRecordSetWithDecryptors(
		context.Background(), set, materializerUnavailableDecryptors("network/node"),
	)
	if err != nil {
		t.Fatal(err)
	}
	self := client.nodes[materializerSelfDID]
	if self == nil || self.Opaque || self.Revoked || self.RecordID != "self-node" || self.MeshIP != "10.200.1.1" ||
		self.Label != "last-good-self" || self.ExpiresAt != expiresAt {
		t.Fatalf("warm opaque self did not preserve typed last-good: %#v", self)
	}
	if response.Node == nil || response.Node.ExpiresAt != expiresAt || nodeRecordExpired(self, now) ||
		!nodeRecordExpired(self, now.Add(2*time.Hour)) {
		t.Fatalf("preserved self expiry was not enforced: node=%#v response=%#v", self, response.Node)
	}

	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "self-node", "2026-07-11T12:00:04Z"), "")
	if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
		t.Fatalf("delete self changed=%v err=%v", changed, err)
	}
	down, err := client.materializeRawMeshRecordSetWithDecryptors(
		context.Background(), set, materializerUnavailableDecryptors("network/node"),
	)
	if err != nil {
		t.Fatal(err)
	}
	revoked := client.nodes[materializerSelfDID]
	if down.Node == nil || len(down.Peers) != 0 || revoked == nil || !revoked.Revoked || revoked.Opaque ||
		revoked.ExpiresAt != revokedSelfExpiry || !nodeRecordExpired(revoked, now) {
		t.Fatalf("self deletion did not commit down map: response=%#v node=%#v", down, revoked)
	}

	renewal := materializerRecord(t, materializerRecordSpec{
		id: "self-renewed", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerSelfDID,
		data:      NodeRecord{MeshIP: "10.200.1.1", Label: "renewed-self", ExpiresAt: renewedExpiry},
		timestamp: "2026-07-11T12:00:05Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(renewal, ""), ""); err != nil || !changed {
		t.Fatalf("apply renewal changed=%v err=%v", changed, err)
	}
	active, err := client.materializeRawMeshRecordSet(context.Background(), set)
	if err != nil {
		t.Fatal(err)
	}
	renewed := client.nodes[materializerSelfDID]
	if active.Node == nil || len(active.Peers) != 1 || renewed == nil || renewed.Revoked || renewed.Opaque ||
		renewed.RecordID != "self-renewed" || renewed.ExpiresAt != renewedExpiry {
		t.Fatalf("renewal did not restore active map: response=%#v node=%#v", active, renewed)
	}
}

func TestMaterializeRawMeshRecordSetColdMissingSelfEmitsDownMapAndRenewal(t *testing.T) {
	peerDID, _ := testDIDJWK(t)
	set, err := newRawMeshRecordSet([]json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: materializerNetworkID, path: "network",
			data: NetworkConfig{Name: "security", MeshCIDR: "10.200.0.0/16"}, timestamp: "2026-07-11T12:00:00Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
			recipient: peerDID, data: NodeRecord{MeshIP: "10.200.1.2"}, timestamp: "2026-07-11T12:00:01Z",
		}),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	down, err := client.materializeRawMeshRecordSet(context.Background(), set)
	if err != nil {
		t.Fatal(err)
	}
	self := client.nodes[materializerSelfDID]
	if down.Node == nil || len(down.Peers) != 0 || self == nil || !self.Revoked || self.ExpiresAt != revokedSelfExpiry {
		t.Fatalf("cold missing-self projection = %#v node=%#v", down, self)
	}
	renewal := materializerRecord(t, materializerRecordSpec{
		id: "self-renewed", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"}, timestamp: "2026-07-11T12:00:02Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(renewal, ""), ""); err != nil || !changed {
		t.Fatalf("apply cold renewal changed=%v err=%v", changed, err)
	}
	active, err := client.materializeRawMeshRecordSet(context.Background(), set)
	if err != nil {
		t.Fatal(err)
	}
	if active.Node == nil || len(active.Peers) != 1 || client.nodes[materializerSelfDID].Revoked {
		t.Fatalf("cold renewal did not restore peers: response=%#v node=%#v", active, client.nodes[materializerSelfDID])
	}
}

func TestApplyPendingStateSelfDeleteCommitsDownBaselineAndRenewal(t *testing.T) {
	peerDID, _ := testDIDJWK(t)
	records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: peerDID, data: NodeRecord{MeshIP: "10.200.1.2"}, timestamp: "2026-07-11T12:00:02Z",
	}))
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, records)

	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "self-node", "2026-07-11T12:00:03Z"), "")
	if err := client.StageTopologyEvent(deleted); err != nil {
		t.Fatal(err)
	}
	down, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if down.Node == nil || len(down.Peers) != 0 || !client.nodes[materializerSelfDID].Revoked {
		t.Fatalf("self delete did not publish down map: response=%#v node=%#v", down, client.nodes[materializerSelfDID])
	}
	client.deltaMu.Lock()
	baseline := client.rawBaseline
	pending := len(client.pendingTopology)
	repair := client.fullReconciliation
	client.deltaMu.Unlock()
	if baseline == nil {
		t.Fatal("self delete discarded raw baseline")
	}
	if _, present := baseline.get("self-node"); present || pending != 0 || repair {
		t.Fatalf("self delete not committed: present=%v pending=%d repair=%v", present, pending, repair)
	}

	renewal := materializerRecord(t, materializerRecordSpec{
		id: "self-renewed", path: "network/node", parentContext: materializerNetworkID,
		recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"}, timestamp: "2026-07-11T12:00:04Z",
	})
	if err := client.StageTopologyEvent(rawRecordTestSubscription(renewal, "")); err != nil {
		t.Fatal(err)
	}
	active, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if active.Node == nil || len(active.Peers) != 1 || client.nodes[materializerSelfDID].Revoked {
		t.Fatalf("self renewal did not restore committed map: response=%#v node=%#v", active, client.nodes[materializerSelfDID])
	}
}

func TestApplyPendingStateSelfDeletePreemptsUnreadableOptionalRecords(t *testing.T) {
	peerDID, _ := testDIDJWK(t)
	records := append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "peer-node", path: "network/node", parentContext: materializerNetworkID,
		recipient: peerDID, data: NodeRecord{MeshIP: "10.200.1.2"}, timestamp: "2026-07-11T12:00:02Z",
	}))
	client := newMaterializerTestClient()
	installDeltaTestBaseline(t, client, records)

	events := []json.RawMessage{
		rawRecordTestDelete(t, "self-node", "2026-07-11T12:00:03Z"),
		materializerRecord(t, materializerRecordSpec{
			id: "relay-cold", path: "network/relay", parentContext: materializerNetworkID,
			data: RelayData{URL: "unreadable-relay.example", Region: "unreadable"}, encrypted: true,
			timestamp: "2026-07-11T12:00:03.100Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "acl-cold", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data: ACLPolicyData{Version: 1, DefaultAction: "deny"}, encrypted: true,
			timestamp: "2026-07-11T12:00:03.200Z",
		}),
	}
	for _, raw := range events {
		if err := client.StageTopologyEvent(rawRecordTestSubscription(raw, "")); err != nil {
			t.Fatal(err)
		}
	}
	down, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatalf("self revocation was blocked by unreadable optional record: %v", err)
	}
	if down.Node == nil || len(down.Peers) != 0 || !client.nodes[materializerSelfDID].Revoked {
		t.Fatalf("batched self delete did not publish down map: response=%#v node=%#v", down, client.nodes[materializerSelfDID])
	}
	client.deltaMu.Lock()
	baseline := client.rawBaseline
	pending := len(client.pendingTopology)
	client.deltaMu.Unlock()
	if baseline == nil {
		t.Fatal("batched self revocation discarded raw baseline")
	}
	for _, recordID := range []string{"relay-cold", "acl-cold"} {
		if _, present := baseline.get(recordID); !present {
			t.Fatalf("committed down baseline lost %s", recordID)
		}
	}
	if _, present := baseline.get("self-node"); present || pending != 0 {
		t.Fatalf("batched down commit incomplete: selfPresent=%v pending=%d", present, pending)
	}

	renewalEvents := []json.RawMessage{
		materializerRecord(t, materializerRecordSpec{
			id: "self-renewed", path: "network/node", parentContext: materializerNetworkID,
			recipient: materializerSelfDID, data: NodeRecord{MeshIP: "10.200.1.1"},
			timestamp: "2026-07-11T12:00:04Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "relay-cold", path: "network/relay", parentContext: materializerNetworkID,
			data:        RelayData{URL: "relay-restored.example", Region: "restored"},
			dateCreated: "2026-07-11T12:00:03.100Z", timestamp: "2026-07-11T12:00:04.100Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "acl-cold", path: "network/aclPolicy", parentContext: materializerNetworkID,
			data:        ACLPolicyData{Version: 2, DefaultAction: "accept"},
			dateCreated: "2026-07-11T12:00:03.200Z", timestamp: "2026-07-11T12:00:04.200Z",
		}),
	}
	for _, raw := range renewalEvents {
		if err := client.StageTopologyEvent(rawRecordTestSubscription(raw, "")); err != nil {
			t.Fatal(err)
		}
	}
	active, err := client.ApplyPendingState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if active.Node == nil || len(active.Peers) != 1 || client.nodes[materializerSelfDID].Revoked ||
		len(client.relays) != 1 || client.relays[0].URL != "relay-restored.example" ||
		client.acl == nil || client.acl.Version != 2 {
		t.Fatalf("renewal did not reparse optional state: response=%#v relays=%#v acl=%#v", active, client.relays, client.acl)
	}
}

func TestMaterializeRawMeshRecordSetOpaquePeerSkippedBeforeFallbackIdentity(t *testing.T) {
	peerDID, _ := testDIDJWK(t)
	set, err := newRawMeshRecordSet(append(materializerBaseRecords(t), materializerRecord(t, materializerRecordSpec{
		id: "opaque-production-peer", path: "network/node", parentContext: materializerNetworkID,
		recipient: peerDID, data: NodeRecord{MeshIP: "10.200.88.88", ExpiresAt: "2099-01-01T00:00:00Z"},
		encrypted: true, timestamp: "2026-07-11T12:00:02Z",
	})), "")
	if err != nil {
		t.Fatal(err)
	}
	client := newMaterializerTestClient()
	response, err := client.materializeRawMeshRecordSetWithDecryptors(
		context.Background(), set, materializerUnavailableDecryptors("network/node"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ghost := client.nodes[peerDID]
	if ghost == nil || !ghost.Opaque || ghost.MeshIP != "" || len(response.Peers) != 0 {
		t.Fatalf("opaque production peer entered map: ghost=%#v peers=%#v", ghost, response.Peers)
	}
	fixture := nodeRecordToNode(1, peerDID, ghost)
	client.applyFallbackMeshIP(fixture)
	if !fixture.MeshIP.IsValid() || fixture.Key == "" {
		t.Fatalf("fixture did not prove fallback/key bypass risk: %#v", fixture)
	}
}

func TestMaterializeRawMeshRecordSetOpaquePeerDoesNotBlockEndpointDelta(t *testing.T) {
	records := append(materializerBaseRecords(t),
		materializerRecord(t, materializerRecordSpec{
			id: "member-record", path: "network/member", parentContext: materializerNetworkID,
			recipient: "did:jwk:member", data: MemberRecord{Label: "member"}, timestamp: "2026-07-11T12:00:02Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "opaque-peer-node", path: "network/member/node", parentContext: materializerNetworkID + "/member-record",
			recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.2"}, encrypted: true,
			timestamp: "2026-07-11T12:00:03Z",
		}),
		materializerRecord(t, materializerRecordSpec{
			id: "self-endpoint-old", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node",
			data: EndpointData{LocalEndpoints: []string{"192.0.2.1:1111"}}, timestamp: "2026-07-11T12:00:04Z",
		}),
	)
	set, err := newRawMeshRecordSet(records, "")
	if err != nil {
		t.Fatal(err)
	}
	decryptCalls := 0
	decryptors := func(_ context.Context, path string) EntryDecryptor {
		if path != "network/member/node" {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			decryptCalls++
			return nil, fmt.Errorf("%w: role audience key unavailable", errAudienceKeyDeliveryAbsent)
		}
	}
	client := newMaterializerTestClient()
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatalf("initial opaque-peer materialization: %v", err)
	}
	if got := client.undecryptablePeers.Load(); got != 1 {
		t.Fatalf("initial undecryptable count = %d, want 1", got)
	}
	if decryptCalls != 1 {
		t.Fatalf("initial decrypt calls = %d, want 1", decryptCalls)
	}
	if _, ok := client.nodeFailures["opaque-peer-node"]; !ok {
		t.Fatalf("node failure episode was not retained: %#v", client.nodeFailures)
	}

	newEndpoint := materializerRecord(t, materializerRecordSpec{
		id: "self-endpoint-new", path: "network/node/endpoint", parentContext: materializerNetworkID + "/self-node", squash: true,
		data: EndpointData{LocalEndpoints: []string{"192.0.2.1:2222"}}, timestamp: "2026-07-11T12:00:05Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(newEndpoint, ""), ""); err != nil || !changed {
		t.Fatalf("endpoint delta changed=%v err=%v", changed, err)
	}
	response, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors)
	if err != nil {
		t.Fatalf("endpoint delta with opaque peer: %v", err)
	}
	if response.Node == nil || len(response.Node.Endpoints) != 1 || response.Node.Endpoints[0] != "192.0.2.1:2222" {
		t.Fatalf("endpoint delta response = %#v", response.Node)
	}
	if got := client.undecryptablePeers.Load(); got != 1 {
		t.Fatalf("unchanged failure episode incremented count to %d", got)
	}
	if decryptCalls != 1 {
		t.Fatalf("unrelated endpoint delta retried unchanged encrypted peer %d times", decryptCalls-1)
	}

	changedPeer := materializerRecord(t, materializerRecordSpec{
		id: "opaque-peer-node", path: "network/member/node", parentContext: materializerNetworkID + "/member-record",
		recipient: materializerPeerDID, data: NodeRecord{MeshIP: "10.200.1.3"}, encrypted: true,
		timestamp: "2026-07-11T12:00:05.500Z",
	})
	if changed, err := set.applySubscriptionMessage(rawRecordTestSubscription(changedPeer, ""), ""); err != nil || !changed {
		t.Fatalf("changed peer winner changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatalf("changed opaque peer materialization: %v", err)
	}
	if decryptCalls != 2 {
		t.Fatalf("changed winner decrypt calls = %d, want exactly 2 total", decryptCalls)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatalf("cached changed opaque peer materialization: %v", err)
	}
	if decryptCalls != 2 {
		t.Fatalf("unchanged changed-winner projection retried decrypt: %d", decryptCalls)
	}

	client.invalidateRawParsedOutcomes()
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatalf("materialize after delivery/full invalidation: %v", err)
	}
	if decryptCalls != 3 {
		t.Fatalf("delivery/full invalidation decrypt calls = %d, want 3", decryptCalls)
	}

	deleted := rawRecordTestSubscription(rawRecordTestDelete(t, "opaque-peer-node", "2026-07-11T12:00:06Z"), "")
	if changed, err := set.applySubscriptionMessage(deleted, ""); err != nil || !changed {
		t.Fatalf("delete opaque peer changed=%v err=%v", changed, err)
	}
	if _, err := client.materializeRawMeshRecordSetWithDecryptors(context.Background(), set, decryptors); err != nil {
		t.Fatalf("materialize opaque-peer deletion: %v", err)
	}
	if _, ok := client.nodeFailures["opaque-peer-node"]; ok {
		t.Fatalf("deleted node failure episode was retained: %#v", client.nodeFailures)
	}
}

type materializerRecordSpec struct {
	id            string
	protocol      string
	path          string
	parentContext string
	recipient     string
	data          any
	timestamp     string
	dateCreated   string
	squash        bool
	encrypted     bool
}

func materializerRecord(t *testing.T, spec materializerRecordSpec) json.RawMessage {
	t.Helper()
	protocol := spec.protocol
	if protocol == "" {
		protocol = protocols.MeshProtocolURI
	}
	timestamp := spec.timestamp
	if timestamp == "" {
		timestamp = time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	}
	dateCreated := spec.dateCreated
	if dateCreated == "" {
		dateCreated = timestamp
	}
	data, ok := spec.data.(json.RawMessage)
	if !ok {
		var err error
		data, err = json.Marshal(spec.data)
		if err != nil {
			t.Fatalf("marshal record %s data: %v", spec.id, err)
		}
	}
	descriptor := map[string]any{
		"interface":        "Records",
		"method":           "Write",
		"protocol":         protocol,
		"protocolPath":     spec.path,
		"dateCreated":      dateCreated,
		"messageTimestamp": timestamp,
	}
	contextID := spec.id
	if spec.parentContext != "" {
		segments := strings.Split(spec.parentContext, "/")
		descriptor["parentId"] = segments[len(segments)-1]
		contextID = spec.parentContext + "/" + spec.id
	}
	if spec.squash {
		descriptor["squash"] = true
	}
	if spec.recipient != "" {
		descriptor["recipient"] = spec.recipient
	}
	message := map[string]any{
		"recordId":    spec.id,
		"contextId":   contextID,
		"descriptor":  descriptor,
		"encodedData": base64.RawURLEncoding.EncodeToString(data),
	}
	if spec.encrypted {
		message["encryption"] = map[string]any{}
	}
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatalf("marshal record %s: %v", spec.id, err)
	}
	return raw
}

func newMaterializerTestClient() *DWNClient {
	return &DWNClient{
		networkRecordID:  materializerNetworkID,
		selfDID:          materializerSelfDID,
		logger:           slog.Default(),
		members:          make(map[string]*MemberRecord),
		nodes:            make(map[string]*NodeRecord),
		endpointFailures: make(map[string]string),
	}
}

func materializerUnavailableDecryptors(paths ...string) func(context.Context, string) EntryDecryptor {
	unavailable := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		unavailable[path] = struct{}{}
	}
	return func(_ context.Context, path string) EntryDecryptor {
		if _, ok := unavailable[path]; !ok {
			return nil
		}
		return func([]byte, *dwncrypto.Encryption) ([]byte, error) {
			return nil, fmt.Errorf("%w: delivery not present", errAudienceKeyDeliveryAbsent)
		}
	}
}
