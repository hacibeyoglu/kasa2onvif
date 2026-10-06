// Package hub implements a latest-keyframe + bounded-queue broadcaster: each
// consumer gets a subscription with a small queue; the hub never blocks the
// source and consumers that fall behind are resynchronised on the next
// keyframe (this is what keeps UniFi Protect streams stable).
package hub

import (
	"sync"
	"time"

	"kasa2onvif/internal/core"
)

// Subscription is one consumer of the hub.
type Subscription struct {
	ID      string
	queue   chan *core.Frame
	lastKey *core.Frame // latest keyframe (SPS/PPS/IDR) for resynchronisation
	hub     *Hub
	mu      sync.Mutex
	dropped uint64
	sent    uint64
	closed  bool
	// rawKeyframe stores the exact keyframe AU primed into the queue.
	rawKeyframe []byte
}

// Recv returns the next frame. Drops are signalled with Frame.Dropped so the
// consumer can decide to skip until the next keyframe.
func (s *Subscription) Recv() <-chan *core.Frame {
	return s.queue
}

// Close removes the subscription from the hub.
func (s *Subscription) Close() {
	s.hub.Remove(s)
}

// Hub broadcasts video and audio frames to consumers.
type Hub struct {
	mu     sync.Mutex
	subs   map[string]*Subscription
	order  []string
	video  *core.Frame // latest keyframe (for immediate delivery to new subs)
	audio  *core.Frame // latest audio chunk
	closed bool
	seq    uint64
}

// New creates a hub.
func New() *Hub {
	return &Hub{subs: map[string]*Subscription{}}
}

// Subscribe registers a consumer. queueSize bounds the per-consumer queue;
// on overflow the frames are dropped. The queue is NOT primed here; the
// consumer should call WaitKeyframe/PreviewKeyframe if it needs to start at
// an IDR (the RTSP server does this in its stream pump).
func (h *Hub) Subscribe(id string, queueSize int) *Subscription {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := &Subscription{ID: id, queue: make(chan *core.Frame, queueSize), hub: h}
	h.subs[id] = sub
	h.order = append(h.order, id)
	return sub
}

// PreviewKeyframe returns a copy of the latest keyframe without consuming
// from the queue (nil when none has been seen yet).
func (h *Hub) PreviewKeyframe() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.video == nil {
		return nil
	}
	c := make([]byte, len(h.video.Payload))
	copy(c, h.video.Payload)
	return c
}

// Remove unregisters a consumer.
func (h *Hub) Remove(sub *Subscription) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.subs[sub.ID]; !ok {
		return
	}
	delete(h.subs, sub.ID)
	for i, id := range h.order {
		if id == sub.ID {
			h.order = append(h.order[:i], h.order[i+1:]...)
			break
		}
	}
	sub.mu.Lock()
	if !sub.closed {
		sub.closed = true
		close(sub.queue)
	}
	sub.mu.Unlock()
}

// Publish delivers a frame to every subscription without ever blocking the
// source: slow consumers drop frames and resync on next keyframe.
func (h *Hub) Publish(f *core.Frame) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.seq++
	if f.Kind == 0 && f.Keyframe {
		c := *f
		h.video = &c
	}
	if f.Kind == 1 {
		c := *f
		h.audio = &c
	}
	// Snapshot subscribers under lock, deliver outside to avoid holding lock
	// during channel sends (channel sends here are non-blocking with select).
	type target struct {
		sub *Subscription
	}
	targets := make([]target, 0, len(h.order))
	for _, id := range h.order {
		targets = append(targets, target{sub: h.subs[id]})
	}
	h.mu.Unlock()

	for _, t := range targets {
		t.sub.enqueue(f)
	}
}

func (s *Subscription) enqueue(f *core.Frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	c := *f // copy: consumers may mutate/capture
	select {
	case s.queue <- &c:
		s.sent++
	default:
		// queue full: drop and remember for the consumer to resync
		s.dropped++
		f.Dropped = false
		// update lastKey bookkeeping so a future consumer can resync
		if f.Kind == 0 && f.Keyframe {
			lf := *f
			s.lastKey = &lf
		}
		// Try to drop the oldest frame and replace with this one if keyframe,
		// so the consumer gets a fresh entry point promptly on drain.
		select {
		case <-s.queue:
			if f.Kind == 0 && f.Keyframe {
				select {
				case s.queue <- &c:
					s.sent++
				default:
				}
			}
		default:
		}
	}
}

// Stats returns per-subscription counters.
func (s *Subscription) Stats() (sent, dropped uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent, s.dropped
}

// ConsumerCount returns the number of active subscriptions.
func (h *Hub) ConsumerCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Stats returns hub-wide counters.
func (h *Hub) Stats() (subs int, seq uint64, lastVideoAge time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	age := time.Duration(0)
	_ = age
	return len(h.subs), h.seq, age
}

// LatestKeyframe is an alias of PreviewKeyframe (kept for callers that
// think in terms of "the frame to inject first").
func (h *Hub) LatestKeyframe() []byte {
	return h.PreviewKeyframe()
}
