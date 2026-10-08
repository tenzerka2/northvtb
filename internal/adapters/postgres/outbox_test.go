package postgres

import (
	"context"
	"sync"
	"testing"
)

func TestOutboxConcurrentDelivery(t *testing.T) {
	db, s, _ := setup(t)
	makeMandate(t, s)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, e := db.DeliverOutbox(ctx, 32)
				if e != nil {
					errs <- e
					return
				}
				if n == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var missing int
	if e := db.DB.QueryRow(`SELECT count(*) FROM north.outbox o LEFT JOIN north.event_inbox i USING(event_id) WHERE o.delivered_at IS NULL OR i.event_id IS NULL`).Scan(&missing); e != nil || missing != 0 {
		t.Fatal(missing, e)
	}
	if n, e := db.DeliverOutbox(ctx, 32); e != nil || n != 0 {
		t.Fatal("duplicate relay", n, e)
	}
}
