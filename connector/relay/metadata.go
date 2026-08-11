package relay

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/mux"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	connectTimeout time.Duration
	noDelay        bool
	nodeID         bool   // pixelated: announce a sticky-egress node id (metadata KV) on BIND
	nodeIDValue    string // pixelated: explicit node id; empty => auto-derive (self egress IP)
	muxCfg         *mux.Config
}

func (c *relayConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "connectTimeout"
		noDelay        = "nodelay"
	)

	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)
	c.md.noDelay = mdutil.GetBool(md, noDelay)
	c.md.nodeID = mdutil.GetBool(md, "nodeID", "nodeid")
	c.md.nodeIDValue = mdutil.GetString(md, "nodeIDValue", "nodeidvalue")

	c.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
		Type:              mdutil.GetString(md, "mux.type"),
		MaxStreamWindow:   mdutil.GetInt(md, "mux.maxStreamWindow"),
	}

	return
}
