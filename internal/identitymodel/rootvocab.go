package identitymodel

// InRootVocabulary reports whether an authenticated, understood event on a fixed-root identity's pinned lineage,
// other than its inception, is in the closed root vocabulary (fixed-root note, "Root vocabulary on the pinned I
// lineage is closed"): grants and cuts (administrative), recognized inert describes/anchors, and the terminal key
// events. Any other event there reads unsupported_root_event, which leaves every act of the identity unknown.
//
// It is the one list the reader's root walk (rootState) and the writer's refusal of an ordinary line by a root
// share, so the two cannot disagree. A second inception on the lineage is outside it.
func InRootVocabulary(e Event) bool {
	switch e {
	case GrantEvent, Inert, CutEvent, RotateKey, RevokeKey:
		return true
	}
	return false
}

// InProfileRootVocabulary is InRootVocabulary for a given profile. A recoverable root's vocabulary adds the
// handover (recoverable-root note §4); the recovery key's statement and a successor's succession are seq-0 lines
// of other keys and are never in a root's lineage. An unknown profile has no vocabulary: nothing is in it.
func InProfileRootVocabulary(p Profile, e Event) bool {
	switch p {
	case FixedRoot:
		return InRootVocabulary(e)
	case RecoverableRoot:
		return InRootVocabulary(e) || e == HandoverEvent
	}
	return false
}
