// Package mesh - ip_allocator.go assigns mesh-internal IP addresses to nodes.
//
// IP allocation within the mesh CIDR (e.g., 100.64.0.0/10):
//   - The network owner gets the first usable address (e.g., 100.64.0.1)
//   - New members are assigned the next available address
//   - Addresses are recorded in the nodeInfo record
//   - Deleted/revoked members' addresses can be reclaimed
//
// For the PoC, allocation is simple and centralized (admin assigns).
// For production, a CRDT-based allocator could enable conflict-free
// allocation across multiple admins.
package mesh
