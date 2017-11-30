package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/govau/cf-common/credhub"
)

type certSource interface {
	// AutoFetchCert will try to fetch a cert now for the hostname and given context (you should set this to timeout)
	AutoFetchCert(ctx context.Context, pkey *rsa.PrivateKey, hostname string) ([][]byte, error)

	// ManualStartChallenge will return instructions on how to proceed. We'll persist it for you
	ManualStartChallenge(ctx context.Context, hostname string) (*acmeChallenge, error)

	// CompleteChallenge and issue cert
	CompleteChallenge(ctx context.Context, pkey *rsa.PrivateKey, hostname string, chal *acmeChallenge) ([][]byte, error)

	SupportsManual() bool
}

type shouldShipOracle interface {
	ShipToProxy(hostname string) bool
}

type certRenewer interface {
	RenewCertNow(hostname, cs string) error
	CanDelete(hostname string) bool
	Sources() []string
	SourceCanManual(string) bool
	StartManualChallenge(hostname string) error
	CompleteChallenge(hostname string) error
}

type daemonConf struct {
	DaysBefore int `yaml:"days_before"`
	Period     int `yaml:"period"`
	Bootstrap  struct {
		Source string `yaml:"source"`
	} `yaml:"bootstrap"`

	fixedHosts []string
	ourHN      string
	storage    certStorage

	certFactories map[string]certSource
	sources       []string
	observers     []certObserver

	updateRequests chan bool
}

func (dc *daemonConf) Sources() []string {
	return dc.sources
}

func (dc *daemonConf) SourceCanManual(cs string) bool {
	cf, ok := dc.certFactories[cs]
	if !ok {
		return false
	}
	return cf.SupportsManual()
}

func (dc *daemonConf) Init(ourHostname string, sm sourceMap, storage certStorage, observers []certObserver, responder responder) error {
	dc.updateRequests = make(chan bool, 1000)

	if dc.Period == 0 {
		return errors.New("period must be specified and non-zero. should be in seconds")
	}
	if dc.DaysBefore == 0 {
		return errors.New("days before must be specified and non-zero. should be in days")
	}

	dc.ourHN = ourHostname
	dc.fixedHosts = []string{
		"proxy-bootstrap", // do first, in case we take longer
		ourHostname,
	}

	dc.certFactories = make(map[string]certSource)
	dc.sources = nil
	for name, val := range sm {
		switch val.Type {
		case "self-signed":
			dc.certFactories[name] = &selfSignedSource{}
		case "acme":
			v := &acmeCertSource{
				EmailContact:    val.Email,
				URL:             val.URL,
				PrivateKey:      val.PrivateKey,
				responderServer: responder,
			}
			err := v.Init()
			if err != nil {
				return err
			}
			dc.certFactories[name] = v

		default:
			return errors.New("unknown cert source type")
		}

		dc.sources = append(dc.sources, name)
	}

	if len(dc.certFactories) == 0 {
		return errors.New("must specify at least one cert source")
	}

	dc.storage = storage

	sort.StringSlice(dc.sources).Sort()

	dc.observers = observers

	return nil
}

func (dc *daemonConf) updateObservers() error {
	certs, err := dc.storage.FetchCerts()
	if err != nil {
		return err
	}
	var retErr error
	for _, ob := range dc.observers {
		err = ob.CertsAreUpdated(certs)
		if err != nil {
			log.Println("erroring updating cert observer, will continue to next but still return failed:", err)
			retErr = err
		}
	}
	return retErr
}

func (dc *daemonConf) RunForever() {
	// Periodic scan loop, this will ping the update request queue
	go func() {
		bootstrapped := false
		for {
			nextSleepSeconds := time.Duration(dc.Period)

			log.Println("starting periodic scan...")
			err := dc.periodicScan()
			if err == nil {
				log.Println("finished successfully")
				bootstrapped = true
			} else {
				log.Println("error in periodic scan, ignoring:", err)
				if credhub.IsCommsRelatedError(err) && !bootstrapped {
					log.Println("looks like a comms related issue, we'll reduce our sleep time")
					nextSleepSeconds = 15
				}
			}

			log.Printf("sleeping for %d...\n", nextSleepSeconds)
			time.Sleep(time.Second * nextSleepSeconds)
		}
	}()

	// Write out config loop
	t := time.NewTimer(time.Second * 5)
	for {
		select {
		case <-dc.updateRequests:
			// Reset our timer to fire after a reasonable period in case new certs also come through
			// first Stop() and drain it, per the docs
			if !t.Stop() {
				<-t.C
			}
			log.Println("got update request, sleeping for a bit and will then action...")
			t.Reset(time.Second * 30)
		case <-t.C:
			// don't come back for a long time
			// we don't have to stop it, because we fired to begin with we know it is drained
			t.Reset(time.Hour * 24 * 365)

			log.Println("updating observers...")
			err := dc.updateObservers()
			if err == nil {
				log.Println("updating observers completed successfully.")
			} else {
				log.Printf("error updating observers, will try again soon: %s\n", err)
				dc.updateRequests <- true
			}
		}
	}
}

func (dc *daemonConf) renewCertIfNeeded(hostname string) error {
	path := pathFromHost(hostname)

	needNew := false

	chc, err := dc.storage.LoadPath(path)
	if err != nil {
		if credhub.IsNotFoundError(err) {
			needNew = true
			chc = nil
		} else {
			return err
		}
	}

	sourceToUse := dc.Bootstrap.Source

	// Note that if a certificate already exists, we won't try to renew it unless there
	// is already a certificate that exists. In that manner new certs won't attempt to be renewed
	// until we're ready. (e.g. while waiting for a DNS response)
	if chc != nil {
		sourceToUse = chc.Source

		if chc.Challenge != nil {
			return errors.New("challenge not empty, we will not try to auto renew, please use console to do manually")
		}

		block, _ := pem.Decode([]byte(chc.Certificate))
		if block == nil {
			return errors.New("no cert found in pem, perhaps this cert hasn't been manually issued yet?")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("invalid cert found in pem")
		}

		pc, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		if pc.NotAfter.Before(time.Now()) {
			return errors.New("cert already expired, we won't try to auto-renew. do so manually via console")
		}

		if pc.NotAfter.Before(time.Now().Add(24 * time.Hour * time.Duration(dc.DaysBefore))) {
			needNew = true
		}
	}

	if !needNew {
		return nil
	}

	err = dc.RenewCertNow(hostname, sourceToUse)
	if err != nil {
		return err
	}

	return nil
}

func (dc *daemonConf) CanDelete(hostname string) bool {
	return !dc.isFixedHost(hostname)
}

func (dc *daemonConf) ShipToProxy(hostname string) bool {
	return hostname != dc.ourHN
}

func (dc *daemonConf) isFixedHost(hostname string) bool {
	for _, hn := range dc.fixedHosts {
		if hn == hostname {
			return true
		}
	}
	return false
}

func (dc *daemonConf) StartManualChallenge(hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	path := pathFromHost(hostname)
	curCert, err := dc.storage.LoadPath(path)
	if err != nil {
		return err
	}

	cf, ok := dc.certFactories[curCert.Source]
	if !ok {
		return fmt.Errorf("no cert source found for: %s", curCert.Source)
	}

	chal, err := cf.ManualStartChallenge(ctx, hostname)
	if err != nil {
		return err
	}

	curCert.Challenge = chal

	err = dc.storage.SavePath(path, curCert)
	if err != nil {
		return err
	}

	return nil
}

func (dc *daemonConf) CompleteChallenge(hostname string) error {
	chd, err := dc.storage.LoadPath(pathFromHost(hostname))
	if err != nil {
		return err
	}

	if chd.Challenge == nil {
		return errors.New("challenge not set")
	}

	return dc.getCertAndSave(hostname, chd.Source, func(ctx context.Context, cf certSource, pkey *rsa.PrivateKey) ([][]byte, error) {
		return cf.CompleteChallenge(ctx, pkey, hostname, chd.Challenge)
	})
}

func (dc *daemonConf) getCertAndSave(hostname, cs string, issuer func(context.Context, certSource, *rsa.PrivateKey) ([][]byte, error)) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	cf, ok := dc.certFactories[cs]
	if !ok {
		return fmt.Errorf("no cert source found for: %s", cs)
	}

	der, err := issuer(ctx, cf, pkey)
	if err != nil {
		return err
	}

	roots := ""
	for _, r := range der[1:] {
		roots += string(pem.EncodeToMemory(&pem.Block{
			Bytes: r,
			Type:  "CERTIFICATE",
		}))
	}

	certType := "admin"
	if dc.CanDelete(hostname) {
		certType = "user"
	}

	err = dc.storage.SavePath(pathFromHost(hostname), &credhubCert{
		Source: cs,
		CA:     roots,
		Type:   certType,
		Certificate: string(pem.EncodeToMemory(&pem.Block{
			Bytes: der[0],
			Type:  "CERTIFICATE",
		})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{
			Bytes: x509.MarshalPKCS1PrivateKey(pkey),
			Type:  "RSA PRIVATE KEY",
		})),
	})
	if err != nil {
		return err
	}

	// yo, we got a cert
	dc.updateRequests <- true

	return nil
}

func (dc *daemonConf) RenewCertNow(hostname, cs string) error {
	return dc.getCertAndSave(hostname, cs, func(ctx context.Context, cf certSource, pkey *rsa.PrivateKey) ([][]byte, error) {
		return cf.AutoFetchCert(ctx, pkey, hostname)
	})
}

func (dc *daemonConf) periodicScan() error {
	var retErr error

	// First, fetch the list of certs.
	// We do this first to ensure our storage layer is up before we try to communicate with
	// any of our CA sources

	// Next fetch all certs, and renew
	certsToDealWith, err := dc.storage.FetchCerts()
	if err != nil {
		return err
	}

	// Now ignore it, and handle our fixed hosts
	for _, fh := range dc.fixedHosts {
		err := dc.renewCertIfNeeded(fh)
		if err != nil {
			log.Println("error, continuing with others:", err)
			retErr = err
		}
	}

	// And now handle the rest.
	for _, cert := range certsToDealWith {
		hn := hostFromPath(cert.path)
		if !dc.isFixedHost(hn) { // we just did these above
			err = dc.renewCertIfNeeded(hn)
			if err != nil {
				log.Println("error, continuing with others:", err)
				retErr = err
			}
		}
	}

	return retErr
}
