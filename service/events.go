package service

import (
	"sync"
	"time"
)

// TokenEvent represents a token-related event
type TokenEvent struct {
	Type      string
	KeyPrefix string
	TokenID   string
	Timestamp time.Time
	Metadata  map[string]any
}

// TokenEventObserver defines the interface for token event observers
type TokenEventObserver interface {
	OnTokenEvent(event TokenEvent)
}

// TokenEventPublisher manages token event observers
type TokenEventPublisher struct {
	observers []TokenEventObserver
	mutex     sync.RWMutex
}

// NewTokenEventPublisher creates a new event publisher
func NewTokenEventPublisher() *TokenEventPublisher {
	return &TokenEventPublisher{
		observers: make([]TokenEventObserver, 0),
	}
}

// Subscribe adds an observer
func (tep *TokenEventPublisher) Subscribe(observer TokenEventObserver) {
	tep.mutex.Lock()
	defer tep.mutex.Unlock()
	tep.observers = append(tep.observers, observer)
}

// Unsubscribe removes an observer
func (tep *TokenEventPublisher) Unsubscribe(observer TokenEventObserver) {
	tep.mutex.Lock()
	defer tep.mutex.Unlock()
	for i, obs := range tep.observers {
		if obs == observer {
			tep.observers = append(tep.observers[:i], tep.observers[i+1:]...)
			break
		}
	}
}

// Publish sends an event to all observers
func (tep *TokenEventPublisher) Publish(event TokenEvent) {
	tep.mutex.RLock()
	defer tep.mutex.RUnlock()
	for _, observer := range tep.observers {
		go observer.OnTokenEvent(event) // Async notification
	}
}

// Example observer implementations
type LoggingObserver struct{}

func (lo *LoggingObserver) OnTokenEvent(event TokenEvent) {
	// Log the event
	// fmt.Printf("Token event: %s for key %s at %s\n", event.Type, event.KeyPrefix, event.Timestamp)
}

type MetricsObserver struct{}

func (mo *MetricsObserver) OnTokenEvent(event TokenEvent) {
	// Update metrics
	// metrics.Counter("token_events").WithTag("type", event.Type).Increment()
}
