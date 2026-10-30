package btctime

// State is a bound's state token (bitcoin-time note §8.1).
type State string

const (
	StateVerified           State = "verified"
	StateVerifiedHistorical State = "verified-historical"
	StatePending            State = "pending"
	StateInsufficient       State = "insufficient-confirmations"
	StateMissingProof       State = "missing-proof"
	StateInvalidProof       State = "invalid-proof"
	StateInvalidAnchor      State = "invalid-anchor"
	StateUnknownHeight      State = "unknown-height"
	StateOrphaned           State = "orphaned"
	StateStaleChain         State = "stale-chain"
	StateUnconfigured       State = "backend-unconfigured"
	StateUnavailable        State = "backend-unavailable"
	StateUnsupported        State = "unsupported"
	// StateRefused is an operational refusal of the anchor (a size limit of this reader, §4 checks 1 and 5). The
	// note's §8.1 list has no token for it; Evidence.Refusal carries the class and reason.
	StateRefused State = "refused"
)

// Quality is the reader's verdict (§8.1): none, local or bitcoin.
type Quality string

const (
	QualityNone    Quality = "none"
	QualityLocal   Quality = "local"
	QualityBitcoin Quality = "bitcoin"
)
