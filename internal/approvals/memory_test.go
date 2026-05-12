package approvals

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// newPending returns a minimal request the tests can enqueue. Tool
// name varies across tests to keep the suite from looking like a
// payments-only feature; the queue itself doesn't care which tool
// is being approved.
func newPending(tool string) PendingRequest {
	return PendingRequest{
		AgentID: "agent-x",
		Tool:    tool,
		Reason:  "policy escalation",
	}
}

func TestMemoryEnqueueAssignsIDAndStatus(t *testing.T) {
	s := NewMemoryStore()
	row, err := s.Enqueue(context.Background(), newPending("send_email_external"))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if row.PendingID == "" {
		t.Error("PendingID not assigned")
	}
	if row.Status != StatusPending {
		t.Errorf("Status=%q want pending", row.Status)
	}
	if row.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestMemoryWaitUnblocksOnDecide(t *testing.T) {
	s := NewMemoryStore()
	row, _ := s.Enqueue(context.Background(), newPending("transfer_funds"))

	var (
		got PendingRequest
		err error
		wg  sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		got, err = s.Wait(ctx, row.PendingID)
	}()

	// Give Wait a chance to register before deciding.
	time.Sleep(20 * time.Millisecond)
	if _, err := s.Decide(context.Background(), row.PendingID, Decision{
		Status: StatusApproved, DecidedBy: "alice@acme",
	}); err != nil {
		t.Fatalf("decide: %v", err)
	}

	wg.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got.Status != StatusApproved {
		t.Errorf("Wait returned status=%q, want approved", got.Status)
	}
	if got.DecidedBy != "alice@acme" {
		t.Errorf("DecidedBy=%q", got.DecidedBy)
	}
	if got.DecidedAt == nil {
		t.Error("DecidedAt not stamped")
	}
}

func TestMemoryWaitTimesOutToTimeoutStatus(t *testing.T) {
	s := NewMemoryStore()
	row, _ := s.Enqueue(context.Background(), newPending("transfer_funds"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got, err := s.Wait(ctx, row.PendingID)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got.Status != StatusTimeout {
		t.Errorf("Status=%q want timeout", got.Status)
	}
	// A subsequent Decide on a timed-out row is a no-op (already
	// decided).
	if _, err := s.Decide(context.Background(), row.PendingID, Decision{Status: StatusApproved}); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("decide-after-timeout err=%v want ErrAlreadyDecided", err)
	}
}

func TestMemoryDoubleDecideIsErrAlreadyDecided(t *testing.T) {
	s := NewMemoryStore()
	row, _ := s.Enqueue(context.Background(), newPending("delete_user"))

	if _, err := s.Decide(context.Background(), row.PendingID, Decision{Status: StatusApproved}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decide(context.Background(), row.PendingID, Decision{Status: StatusRejected}); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("second decide err=%v want ErrAlreadyDecided", err)
	}
}

func TestMemoryDecideRejectsInvalidStatus(t *testing.T) {
	s := NewMemoryStore()
	row, _ := s.Enqueue(context.Background(), newPending("grant_role"))
	for _, st := range []Status{"", "foo", StatusPending, StatusTimeout} {
		if _, err := s.Decide(context.Background(), row.PendingID, Decision{Status: st}); err == nil {
			t.Errorf("Decide accepted invalid Status=%q", st)
		}
	}
}

func TestMemoryListFiltersByStatus(t *testing.T) {
	s := NewMemoryStore()
	a, _ := s.Enqueue(context.Background(), newPending("a"))
	b, _ := s.Enqueue(context.Background(), newPending("b"))
	_, _ = s.Enqueue(context.Background(), newPending("c"))

	_, _ = s.Decide(context.Background(), a.PendingID, Decision{Status: StatusApproved})
	_, _ = s.Decide(context.Background(), b.PendingID, Decision{Status: StatusRejected})

	pending, err := s.List(context.Background(), ListFilter{Status: StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pending))
	}
	if pending[0].Tool != "c" {
		t.Errorf("filtered list returned unexpected row: %+v", pending[0])
	}

	approved, _ := s.List(context.Background(), ListFilter{Status: StatusApproved})
	if len(approved) != 1 || approved[0].Tool != "a" {
		t.Errorf("approved filter wrong: %+v", approved)
	}
}

func TestMemoryWaitOnUnknownID(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Wait(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

// RequiresStepUp must survive Enqueue → Get → List unchanged. It's
// metadata the console reads to gate the Approve button on step-up;
// dropping it on either path defeats the gate.
func TestMemoryRequiresStepUpRoundtrip(t *testing.T) {
	s := NewMemoryStore()
	req := newPending("delete_record")
	req.RequiresStepUp = true
	row, err := s.Enqueue(context.Background(), req)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !row.RequiresStepUp {
		t.Error("Enqueue dropped RequiresStepUp")
	}

	got, err := s.Get(context.Background(), row.PendingID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.RequiresStepUp {
		t.Error("Get dropped RequiresStepUp")
	}

	list, err := s.List(context.Background(), ListFilter{Status: StatusPending})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || !list[0].RequiresStepUp {
		t.Errorf("List dropped RequiresStepUp: %+v", list)
	}

	// Default (omitted) must survive as false.
	req2 := newPending("read_invoice")
	row2, _ := s.Enqueue(context.Background(), req2)
	got2, _ := s.Get(context.Background(), row2.PendingID)
	if got2.RequiresStepUp {
		t.Error("RequiresStepUp leaked true on a row that never set it")
	}
}
