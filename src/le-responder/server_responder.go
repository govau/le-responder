package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dmksnnk/sentryhook"
	"github.com/meatballhat/negroni-logrus"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
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

	n := negroni.New()
	nl := negronilogrus.NewMiddlewareFromLogger(log.StandardLogger(), "web")
	nl.Before = func(entry *log.Entry, req *http.Request, remoteAddr string) *log.Entry {
		return entry.WithFields(log.Fields{
			"request":   req.RequestURI,
			"hostname":  req.Host,
			"userAgent": req.UserAgent(),
			"method":    req.Method,
			"remote":    remoteAddr,
		})
	}
	n.Use(nl)
	n.Use(negroni.NewRecovery())
	n.UseHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// logging setup
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	hook := sentryhook.New(nil)                  // will use raven.DefaultClient, or provide custom client
	hook.SetAsync(log.ErrorLevel)                // async (non-blocking) hook for errors
	hook.SetSync(log.PanicLevel, log.FatalLevel) // sync (blocking) for fatal stuff
	log.AddHook(hook)

	log.Fatal((&http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second, // we recently ended up with a huge amount of conns left open
		Addr:         fmt.Sprintf(":%d", sr.Port),
		Handler:      n,
	}).ListenAndServe())
}
