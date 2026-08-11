package relay

// MetaKeyNodeID is the relay MetadataFeature key under which a worker announces
// its sticky-egress tunnel id (pixelated fork). It is a dedicated metadata key,
// kept separate from the auth username, so a real login is never mistaken for a
// tunnel id — the relay does sticky routing only when it sees this key.
const MetaKeyNodeID = "egress-nodeid"
