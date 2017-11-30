package main

import (
	"errors"
	"io/ioutil"
	"net/url"

	"github.com/govau/cf-common/credhub"
	yaml "gopkg.in/yaml.v2"
)

type sourceMap map[string]struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	PrivateKey string `yaml:"private_key"`
	URL        string `yaml:"url"`
	Email      string `yaml:"email"`
}

type config struct {
	Sources sourceMap `yaml:"sources"`

	Daemon daemonConf `yaml:"daemon"`

	Data struct {
		CredHub credhub.Client `yaml:"credhub"`
	} `yaml:"data"`

	Servers struct {
		ACME  serverResponder `yaml:"acme_responder"`
		Admin adminServer     `yaml:"admin_ui"`
	} `yaml:"servers"`

	Output outputObserver `yaml:"output"`
}

func newConf(configPath string) (*config, error) {
	if configPath == "" {
		return nil, errors.New("must specify a config path")
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var c config
	err = yaml.Unmarshal(data, &c)
	if err != nil {
		return nil, err
	}

	// Parse hostname here, as it's used in a number of places
	u, err := url.Parse(c.Servers.Admin.ExternalURL)
	if err != nil {
		return nil, err
	}
	hn := u.Hostname()
	if hn == "" {
		return nil, errors.New("admin external url must be specified")
	}

	err = c.Data.CredHub.Init()
	if err != nil {
		return nil, err
	}

	ccs := &certStore{
		CredHub: &c.Data.CredHub,
	}

	err = c.Output.Init(&c.Daemon)
	if err != nil {
		return nil, err
	}

	err = c.Daemon.Init(hn, c.Sources, ccs, []certObserver{
		&c.Servers.Admin,
		&c.Output,
	}, &c.Servers.ACME)
	if err != nil {
		return nil, err
	}

	err = c.Servers.ACME.Init(c.Servers.Admin.ExternalURL)
	if err != nil {
		return nil, err
	}

	err = c.Servers.Admin.Init(ccs, &c.Daemon, hn)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (c *config) RunForever() {
	go c.Servers.Admin.RunForever()
	go c.Servers.ACME.RunForever()
	c.Daemon.RunForever()
}
