package main

import (
	"sync"
	"time"
)

type KeyValue struct {
	mu   sync.Mutex
	data map[string]Item
	stop chan struct{}
}

type Item struct {
	Value   interface{}
	Expires time.Time
}

func NewKeyValue() *KeyValue {
	kv := &KeyValue{
		data: make(map[string]Item),
		stop: make(chan struct{}),
	}
	go kv.startCleanup()
	return kv
}

func (kv *KeyValue) Set(key string, value interface{}, ttl time.Duration) {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	expires := time.Now().Add(ttl)
	kv.data[key] = Item{Value: value, Expires: expires}
}

func (kv *KeyValue) Get(key string) (interface{}, bool) {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	item, ok := kv.data[key]
	if !ok || item.Expires.Before(time.Now()) {
		return nil, false
	}
	return item.Value, true
}

func (kv *KeyValue) Delete(key string) {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	delete(kv.data, key)
}

func (kv *KeyValue) startCleanup() {
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			kv.mu.Lock()
			for key, item := range kv.data {
				if item.Expires.Before(time.Now()) {
					delete(kv.data, key)
				}
			}
			kv.mu.Unlock()
		case <-kv.stop:
			ticker.Stop()
			return
		}
	}
}
