package main

import (
	"context"
	"time"
)

// Periodic writes bound normal crash loss to the last five seconds. A write
// error remains latched until restart after repair; new SSH/channels fail
// closed and the management snapshot reports the error.
func runMetering(ctx context.Context, ops *Operations, gateway *Gateway) {
	sample := time.NewTicker(time.Second)
	defer sample.Stop()
	persist := time.NewTicker(5 * time.Second)
	defer persist.Stop()
	ops.Sample(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-sample.C:
			ops.Sample(now)
			if gateway != nil {
				gateway.Recheck()
			}
		case <-persist.C:
			_ = ops.Flush()
			if gateway != nil {
				gateway.Recheck()
			}
		}
	}
}
