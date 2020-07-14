package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dmksnnk/sentryhook"
	"github.com/meatballhat/negroni-logrus"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/govau/cf-common/uaa"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type adminServer struct {
	Port int `yaml:"port"`
	UAA  struct {
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		InternalURL  string   `yaml:"internal_url"`
		ExternalURL  string   `yaml:"external_url"`
		CACerts      []string `yaml:"ca_certs"`
	} `yaml:"uaa"`
	ExternalURL     string   `yaml:"external_url"`
	CSRFKey         string   `yaml:"csrf_key"`
	InsecureCookies bool     `yaml:"insecure_cookies"`
	AllowedUsers    []string `yaml:"allowed_users"`

	cookies     *sessions.CookieStore
	storage     certStorage
	certRenewer certRenewer
	ourHostname string

	ourCertMutex sync.RWMutex
	ourCert      *tls.Certificate
}

func (as *adminServer) Init(storage certStorage, certRenewer certRenewer, ourHostname string) error {
	as.cookies = uaa.MustCreateBasicCookieHandler(false)
	as.storage = storage
	as.certRenewer = certRenewer
	as.ourHostname = ourHostname
	return nil
}

func (as *adminServer) CertsAreUpdated(certs []*credhubCert) error {
	for _, cert := range certs {
		hn := hostFromPath(cert.path)
		if hn != as.ourHostname {
			// skip, not us
			continue
		}
		tlsCert, err := tls.X509KeyPair([]byte(fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cert.Certificate), strings.TrimSpace(cert.CA))), []byte(cert.PrivateKey))
		if err != nil {
			return err
		}
		as.ourCertMutex.Lock()
		as.ourCert = &tlsCert
		as.ourCertMutex.Unlock()
		return nil
	}
	return nil // noop
}

func (as *adminServer) RunForever() {
	// logging setup
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	hook := sentryhook.New(nil)                        // will use raven.DefaultClient, or provide custom client
	hook.SetAsync(logrus.ErrorLevel)                   // async (non-blocking) hook for errors
	hook.SetSync(logrus.PanicLevel, logrus.FatalLevel) // sync (blocking) for fatal stuff
	logrus.AddHook(hook)

	log.Println("admin server exit:", (&http.Server{
		Addr: fmt.Sprintf(":%d", as.Port),
		Handler: (&uaa.LoginHandler{
			Cookies: as.cookies,
			UAA: &uaa.Client{
				URL:          as.UAA.InternalURL,
				CACerts:      as.UAA.CACerts,
				ClientID:     as.UAA.ClientID,
				ClientSecret: as.UAA.ClientSecret,
				ExternalURL:  as.UAA.ExternalURL,
			},
			Scopes: []string{
				"openid",
			},
			AllowedUsers:   as.AllowedUsers,
			BaseURL:        as.ExternalURL,
			ExternalUAAURL: as.UAA.ExternalURL,
			Logger:         log.New(os.Stderr, "", log.LstdFlags),
			ShouldIgnore: func(r *http.Request) bool {
				switch r.URL.Path {
				case "/favicon.ico", "/metrics":
					return true
				default:
					return false
				}
			},
		}).Wrap(as.createAdminHandler()),
		TLSConfig: &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				as.ourCertMutex.RLock()
				defer as.ourCertMutex.RUnlock()
				if as.ourCert == nil {
					return nil, errors.New("we don't have a cert yet")
				}
				return as.ourCert, nil
			},
		},
	}).ListenAndServeTLS("", "")) // we can leave empty as we already have set via tls.Config
}

func (as *adminServer) add(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	return map[string]interface{}{
		"sources": as.certRenewer.Sources(),
	}, nil
}

func (as *adminServer) source(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	hostname := hostFromPath(r.FormValue("path"))
	if hostname == "" {
		as.flashMessage(w, r, "cannot find cert")
		http.Redirect(w, r, "/", http.StatusFound)
		return nil, nil
	}
	return map[string]interface{}{
		"host":    hostname,
		"sources": as.certRenewer.Sources(),
	}, nil
}

func (as *adminServer) flashMessage(w http.ResponseWriter, r *http.Request, m string) {
	session, _ := as.cookies.Get(r, "f")
	log.Println(m)
	session.AddFlash(m)
	session.Save(r, w)
}

func (as *adminServer) update(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	switch r.FormValue("action") {
	case "create":
		hostname := r.FormValue("host")
		if len(hostname) == 0 {
			as.flashMessage(w, r, "empty hostname")
			break
		}
		path := pathFromHost(hostname)

		// Look to see if it exists
		_, err := as.storage.LoadPath(path)
		if err == nil {
			as.flashMessage(w, r, "already managed")
			break
		}

		source := r.FormValue("source")
		if len(source) == 0 {
			as.flashMessage(w, r, "empty source")
			break
		}

		err = as.storage.SavePath(path, &credhubCert{
			Source: source,
		})
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

	case "delete":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			as.flashMessage(w, r, "cannot find cert")
			break
		}

		if !as.certRenewer.CanDelete(hostname) {
			as.flashMessage(w, r, "not allowed to delete cert for this server")
			break
		}

		err := as.storage.DeletePath(pathFromHost(hostname))
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

		as.flashMessage(w, r, "cert successfully deleted")
		break

	case "auto":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			as.flashMessage(w, r, "cannot find cert")
			break
		}

		chd, err := as.storage.LoadPath(pathFromHost(hostname))
		if err != nil {
			as.flashMessage(w, r, err.Error())
		}

		err = as.certRenewer.RenewCertNow(hostname, chd.Source)
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

		as.flashMessage(w, r, "cert successfully renewed")
		break

	case "manual":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			as.flashMessage(w, r, "cannot find cert")
			break
		}

		err := as.certRenewer.StartManualChallenge(hostname)
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

		as.flashMessage(w, r, "cert challenge started")
		break

	case "complete":
		hostname := hostFromPath(r.FormValue("path"))
		if hostname == "" {
			as.flashMessage(w, r, "cannot find cert")
			break
		}

		err := as.certRenewer.CompleteChallenge(hostname)
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

		as.flashMessage(w, r, "cert issued")
		break

	case "source":
		hostname := r.FormValue("host")
		if len(hostname) == 0 {
			as.flashMessage(w, r, "empty hostname")
			break
		}
		path := pathFromHost(hostname)

		// Look to see if it exists
		existing, err := as.storage.LoadPath(path)
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

		source := r.FormValue("source")
		if len(source) == 0 {
			as.flashMessage(w, r, "empty source")
			break
		}

		existing.Source = source

		err = as.storage.SavePath(path, existing)
		if err != nil {
			as.flashMessage(w, r, err.Error())
			break
		}

	default:
		as.flashMessage(w, r, "unknown action")
		break
	}

	http.Redirect(w, r, "/", http.StatusFound)
	return nil, nil
}

type uiCert struct {
	Name          string
	Path          string
	ShowDelete    bool
	ShowRenew     bool
	ShowManual    bool
	DaysRemaining int
	CredHubCert   *credhubCert
}

func (as *adminServer) home(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error) {
	// Fetch list of certs
	certs, err := as.storage.FetchCerts()
	if err != nil {
		return nil, err
	}

	certsForUI := make([]uiCert, len(certs))
	for i, curCred := range certs {
		nameToShow := hostFromPath(curCred.path)
		if nameToShow == "" {
			nameToShow = "cannot decode: " + string(curCred.path)
		}

		daysRemaining := -1

		if curCred.Certificate != "" {
			block, _ := pem.Decode([]byte(curCred.Certificate))
			if block == nil {
				return nil, errors.New("no cert found in pem")
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, errors.New("invalid cert found in pem")
			}

			pc, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			daysRemaining = int(pc.NotAfter.Sub(time.Now()).Hours() / 24)
		}

		certsForUI[i] = uiCert{
			Name:          nameToShow,
			Path:          curCred.path,
			DaysRemaining: daysRemaining,
			ShowDelete:    as.certRenewer.CanDelete(nameToShow),
			ShowRenew:     true,
			ShowManual:    as.certRenewer.SourceCanManual(curCred.Source),
			CredHubCert:   curCred,
		}
	}

	sort.Slice(certsForUI, func(i, j int) bool {
		return certsForUI[i].Name < certsForUI[j].Name
	})

	session, _ := as.cookies.Get(r, "f")
	flashes := session.Flashes()
	if len(flashes) != 0 {
		session.Save(r, w)
	}

	return map[string]interface{}{
		"certs":    certsForUI,
		"messages": flashes,
	}, nil
}

// Fetch the logged in user, and create a cloudfoundry client object and pass that to the underlying real handler.
// Finally, if a template name is specified, and no error returned, execute the template with the values returned
func (as *adminServer) wrapWithClient(tmpl string, f func(vars map[string]string, liu *uaa.LoggedInUser, w http.ResponseWriter, r *http.Request) (map[string]interface{}, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		liu, ok := r.Context().Value(uaa.KeyLoggedInUser).(*uaa.LoggedInUser)
		if !ok {
			log.Println("bad type")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		toPass, err := f(mux.Vars(r), liu, w, r)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// then we must have already redirected or similar
		if toPass == nil {
			return
		}

		// If no template is desired, then stop here
		if tmpl == "" {
			return
		}

		data, err := Asset("data/" + tmpl)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		toPass["user"] = liu
		toPass[csrf.TemplateTag] = csrf.TemplateField(r)
		template.Must(template.New("orgs").Parse(string(data))).Execute(w, toPass)
	}
}

func (as *adminServer) createAdminHandler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", as.wrapWithClient("index.html", as.home))
	r.HandleFunc("/add", as.wrapWithClient("add.html", as.add))
	r.HandleFunc("/source", as.wrapWithClient("source.html", as.source))
	r.HandleFunc("/update", as.wrapWithClient("", as.update)) // will redirect back to home

	// This URL is not secured, and excluded in the wrapper earlier
	r.Handle("/metrics", promhttp.Handler())

	// TODO, check whether cast is really the right thing here...

	n := negroni.New()
	nl := negronilogrus.NewMiddlewareFromLogger(logrus.StandardLogger(), "web")
	nl.Before = func(entry *logrus.Entry, req *http.Request, remoteAddr string) *logrus.Entry {
		return entry.WithFields(logrus.Fields{
			"request":   req.RequestURI,
			"hostname":  req.Host,
			"userAgent": req.UserAgent(),
			"method":    req.Method,
			"remote":    remoteAddr,
		})
	}
	n.Use(nl)
	n.Use(negroni.NewRecovery())
	n.UseHandler(r)

	return csrf.Protect([]byte(as.CSRFKey))(n)
}
