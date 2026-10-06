// Package core holds small shared types used across the doorbell proxy.
package core

import "time"

// Frame is one video access unit or audio chunk flowing through the proxy.
type Frame struct {
	Kind      uint8 // 0 = video (H.264 Annex-B access unit), 1 = audio (G.711u)
	Payload   []byte
	Timestamp time.Duration // presentation timestamp; monotonic since stream start
	Keyframe  bool
	Dropped   bool // set by the hub when the frame was dropped for a slow consumer
}
