package flow

// AppConfidence tells how an application classification was obtained.
type AppConfidence uint8

const (
	AppUnknown AppConfidence = iota // no classification
	AppByPort                       // guessed from the L4 ports only
	AppByIP                         // guessed from the IP addresses only
	AppByDPI                        // detected by inspecting the packet payload
)

// AppMatch is the result of classifying one packet.
type AppMatch struct {
	Name       string
	ID         uint16
	Confidence AppConfidence
}

// AppClassifier classifies a single L3 packet (starting at the IP header).
// Implementations are not safe for concurrent use.
type AppClassifier interface {
	Classify(l3 []byte, tsMillis int64) AppMatch
	Close()
}

// Engine IDs used in the "engine:id" application identifiers.
const (
	appEngineL4Port = 3  // IANA L4 port, the engine used by /etc/objects/applications
	appEngineNDPI   = 13 // same engine the redborder-flow-agent uses for nDPI ids
)
