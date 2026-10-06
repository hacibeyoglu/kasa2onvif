package hub

import (
	"testing"
	"time"

	"kasa2onvif/internal/core"
)

func TestSubscribePrimeWithKeyframe(t *testing.T) {
	h := New()
	// publish a keyframe; a later subscriber can preview it before frames flow
	h.Publish(&core.Frame{Kind: 0, Keyframe: true, Payload: []byte("idr")})
	sub := h.Subscribe("c1", 4)
	kf := h.PreviewKeyframe()
	if kf == nil || string(kf) != "idr" {
		t.Fatalf("preview keyframe = %v", kf)
	}
	// queue itself starts empty now (priming is the consumer's decision)
	select {
	case f := <-sub.Recv():
		t.Errorf("unexpected primed frame: %+v", f)
	default:
	}
}

func TestSlowConsumerResync(t *testing.T) {
	h := New()
	sub := h.Subscribe("c1", 2)
	// overflow the queue
	for i := 0; i < 10; i++ {
		h.Publish(&core.Frame{Kind: 0, Payload: []byte("p")})
	}
	// publish a keyframe: should replace a slot
	h.Publish(&core.Frame{Kind: 0, Keyframe: true, Payload: []byte("idr")})
	deadline := time.After(time.Second)
	got := 0
	for {
		select {
		case <-sub.Recv():
			got++
			if got >= 2 {
				return
			}
		case <-deadline:
			if got == 0 {
				t.Fatal("no frames received")
			}
			return
		}
	}
}

func TestRemoveCloses(t *testing.T) {
	h := New()
	sub := h.Subscribe("c1", 2)
	sub.Close()
	if _, ok := <-sub.Recv(); ok {
		t.Error("channel should be closed")
	}
	if h.ConsumerCount() != 0 {
		t.Error("consumer not removed")
	}
}
