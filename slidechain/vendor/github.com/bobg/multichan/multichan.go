package multichan

import (
	"context"
	"fmt"
	"reflect"
	"sync"
)

// W is the writing end of a one-to-many data channel.
type W struct {
	mu   sync.Mutex
	cond sync.Cond

	zero     interface{}  // the zero value of this channel
	zerotype reflect.Type // the type of the zero value

	closed bool

	head *item

	pendingReaders []*R // readers that don't have their next field set yet
}

// Each item points to the next newer item in the queue.
type item struct {
	next *item
	val  interface{}
}

// R is the reading end of a one-to-many data channel.
type R struct {
	w *W

	// Points to a pointer to the next item the reader will return.
	// This is nil for a new reader.
	// The first time Write is called after a particular reader is created,
	// this gets set to a pointer to the new item.
	// Thereafter,
	// each time read consumes an item,
	// this gets set to the address of that item's "next" field.
	//
	// (Why a pointer to a pointer?
	// If the reader consumes the newest item in the queue,
	// that item's "next" field is nil.
	// When a new item is added with Write,
	// that same field is updated to point to it;
	// so we point to that field in order to see that update.)
	next **item
}

// New produces a new multichan writer.
// Its argument is the zero value that readers will see
// when reading from a closed multichan,
// (or when non-blockingly reading from an unready multichan).
func New(zero interface{}) *W {
	w := &W{
		zero:     zero,
		zerotype: reflect.TypeOf(zero),
	}
	w.cond.L = &w.mu
	return w
}

// Write adds an item to the multichan.
// Its type must match
// (i.e., must be assignable to <https://golang.org/ref/spec#Assignability>)
// that of the zero value passed to New.
//
// Each item written to w remains in an internal queue until the last reader has consumed it.
// Readers added later to a multichan may miss items added earlier.
func (w *W) Write(val interface{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	t := reflect.TypeOf(val)
	if !t.AssignableTo(w.zerotype) {
		panic(fmt.Sprintf("cannot write %s to multichan of %s", t, w.zerotype))
	}

	newItem := &item{val: val}
	oldHead := w.head
	w.head = newItem
	if oldHead != nil {
		oldHead.next = newItem
	}

	for _, r := range w.pendingReaders {
		r.next = &newItem
	}
	w.pendingReaders = nil

	w.cond.Broadcast()
}

// Close closes the writing end of a multichan,
// signaling to readers that the stream has ended.
// Reading past the end of the stream produces the zero value that was passed to New.
func (w *W) Close() {
	w.mu.Lock()
	w.closed = true
	w.cond.Broadcast()
	w.mu.Unlock()
}

// Reader adds a new reader to the multichan and returns it.
// Readers consume resources in the multichan and should be disposed of (with Dispose) when no longer needed.
func (w *W) Reader() *R {
	w.mu.Lock()
	defer w.mu.Unlock()
	r := &R{w: w}
	w.pendingReaders = append(w.pendingReaders, r)
	return r
}

// Read reads the next item in the multichan.
// It blocks until an item is ready to read or its context is canceled.
// If the multichan is closed and the last item has already been consumed,
// or the context is canceled,
// this returns the multichan's zero value (see New) and false.
// Otherwise it returns the next value and true.
// The context argument may be nil.
func (r *R) Read(ctx context.Context) (interface{}, bool) {
	if ctx != nil {
		done := make(chan struct{})
		defer close(done)

		go func() {
			select {
			case <-ctx.Done():
				r.w.mu.Lock()
				r.w.cond.Broadcast()
				r.w.mu.Unlock()

			case <-done:
			}
		}()
	}

	r.w.mu.Lock()
	defer r.w.mu.Unlock()

	for (ctx == nil || ctx.Err() == nil) && !r.w.closed && (r.next == nil || *r.next == nil) {
		r.w.cond.Wait()
	}
	if r.next != nil && *r.next != nil {
		val := (*r.next).val
		r.next = &(*r.next).next
		return val, true
	}
	return r.w.zero, false
}

// NBRead does a non-blocking read on the multichan.
// If the multichan is closed and the last item has already been consumed,
// or if no next item is ready to read,
// this returns the multichan's zero value (see New) and false.
// Otherwise it returns the next value and true.
func (r *R) NBRead() (interface{}, bool) {
	r.w.mu.Lock()
	defer r.w.mu.Unlock()
	if r.next != nil && *r.next != nil {
		val := (*r.next).val
		r.next = &(*r.next).next
		return val, true
	}
	return r.w.zero, false
}

// Dispose removes r from its multichan, freeing up resources.
// It is an error to make further method calls on r after Dispose.
func (r *R) Dispose() {
	// Do nothing. (An earlier implementation had code here.)
}
