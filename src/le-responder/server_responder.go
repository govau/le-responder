package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
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
	log.Fatal((&http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second, // we recently ended up with a huge amount of conns left open
		Addr:         fmt.Sprintf(":%d", sr.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				// Convenience for admins who accidentally drop the https
				http.Redirect(w, r, sr.uiManager, http.StatusMovedPermanently)
				return
			}
			sr.challengeMutex.RLock()
			v, ok := sr.challengeResponse[r.URL.Path]
			sr.challengeMutex.RUnlock()
			if !ok {
				log.Printf("404 %s", r.URL.String())
				http.NotFound(w, r)
				return
			}
			w.Write(v)
		}),
	}).ListenAndServe())
}
