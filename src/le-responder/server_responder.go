package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
)

type serverResponder struct {
	Port int `yaml:"port"`

	uiManager         string
	challengeMutex    sync.RWMutex
	challengeResponse map[string][]byte
}

func (sr *serverResponder) Init(extUrlForConvenience string) error {
	sr.challengeResponse = make(map[string][]byte)
	sr.uiManager = extUrlForConvenience
	return nil
}

func (sr *serverResponder) SetChallengeValue(k string, v []byte) error {
	sr.challengeMutex.Lock()
	sr.challengeResponse[k] = v
	sr.challengeMutex.Unlock()
	return nil
}

func (sr *serverResponder) ClearChallengeValue(k string) {
	sr.challengeMutex.Lock()
	delete(sr.challengeResponse, k)
	sr.challengeMutex.Unlock()
}

func (sr *serverResponder) RunForever() {
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", sr.Port), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// Convenience for admins who accidentally drop the https
			http.Redirect(w, r, sr.uiManager, http.StatusMovedPermanently)
			return
		}
		sr.challengeMutex.RLock()
		v, ok := sr.challengeResponse[r.URL.Path]
		sr.challengeMutex.RUnlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(v)
	})))
}
