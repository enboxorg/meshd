// Package dwn provides an HTTP client for interacting with Decentralized Web Nodes.
//
// The client supports the core DWN interfaces needed for mesh coordination:
//   - RecordsWrite: create/update records (nodeInfo, endpoints, members, etc.)
//   - RecordsRead: read a single record by ID or filter
//   - RecordsQuery: query records with filters, sorting, pagination
//   - RecordsSubscribe: real-time WebSocket subscriptions to record changes
//   - RecordsDelete: delete records (member revocation, etc.)
//   - ProtocolsConfigure: install protocols on a DWN
//   - ProtocolsQuery: check which protocols are installed
//
// All messages are signed with the caller's DID key before sending.
// Encrypted records include JWE encryption metadata.
package dwn
