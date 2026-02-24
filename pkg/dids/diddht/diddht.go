// Copied from github.com/enboxorg/web5-go — will be replaced by a shared enbox Go library.
package diddht

import (
	"context"
	"net/http"
	"sync"

	"github.com/enboxorg/dwn-mesh/pkg/dids/diddht/internal/bep44"
	"github.com/enboxorg/dwn-mesh/pkg/dids/diddht/internal/pkarr"
)

const defaultGatewayURL = "https://enbox-did-dht.fly.dev"

// gateway is the internal interface used to publish Pakrr messages to the DHT
type gateway interface {
	Put(didID string, payload *bep44.Message) error
	PutWithContext(ctx context.Context, didID string, payload *bep44.Message) error

	Fetch(didID string) (*bep44.Message, error)
	FetchWithContext(ctx context.Context, didID string) (*bep44.Message, error)
}

var defaultGateway gateway
var once sync.Once

// getDefaultGateway returns the default Pkarr relay client.
func getDefaultGateway() gateway {
	once.Do(func() {
		defaultGateway = pkarr.NewClient(defaultGatewayURL, http.DefaultClient)
	})

	return defaultGateway
}
