package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"log"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
)

type acmObs struct {
	Region  string   `yaml:"region"`
	Sources []string `yaml:"source"` // only certs matching sources will be added

	// Recommend leaving empty and will use IAM role instead:
	AccessKey    string `yaml:"access_key"`
	AccessSecret string `yaml:"access_secret"`

	awsMutex   sync.Mutex
	awsSession *session.Session

	// Hostname to ARN cache
	arns map[string]string

	// ARN to cert fingerprint
	fingerprints map[string][]byte
}

// must already be in mutex with valid AWS sessions
func (a *acmObs) getCurrentFingerprint(arn string) ([]byte, error) {
	fp, ok := a.fingerprints[arn]
	if ok {
		return fp, nil
	}

	out, err := acm.New(a.awsSession).GetCertificate(&acm.GetCertificateInput{
		CertificateArn: aws.String(arn),
	})
	if err != nil {
		return nil, err
	}

	fp, err = certFingerprint([]byte(*out.Certificate))
	if err != nil {
		return nil, err
	}

	a.fingerprints[arn] = fp
	return fp, nil
}

// must already be in mutex with valid AWS sessions
// return empty string and no error if not found and known not to exist
func (a *acmObs) getARNforHost(hn string) (string, error) {
	arn, ok := a.arns[hn]
	if ok {
		return arn, nil
	}

	// refresh our cache
	a.arns = make(map[string]string)
	err := acm.New(a.awsSession).ListCertificatesPages(&acm.ListCertificatesInput{
		MaxItems: aws.Int64(100),
	}, func(page *acm.ListCertificatesOutput, lastPage bool) bool {
		for _, cert := range page.CertificateSummaryList {
			a.arns[*cert.DomainName] = a.arns[*cert.CertificateArn]
		}
		return true
	})
	if err != nil {
		return "", err
	}

	arn, ok = a.arns[hn]
	if ok {
		return arn, nil
	}

	// now, set it as empty so that we don't scan again next time
	a.arns[hn] = ""
	return "", nil
}

// must already be in mutex
func (a *acmObs) initAWSSessionAndCaches() error {
	if a.arns == nil {
		a.arns = make(map[string]string)
	}

	if a.fingerprints == nil {
		a.fingerprints = make(map[string][]byte)
	}

	if a.awsSession != nil {
		return nil
	}

	var creds *credentials.Credentials
	// if not specified, assume EC2RoleProvider
	if a.AccessKey == "" { // if not specified, assume EC2RoleProvider
		sessionForMetadata, err := session.NewSession()
		if err != nil {
			return err
		}
		creds = credentials.NewCredentials(&ec2rolecreds.EC2RoleProvider{
			Client: ec2metadata.New(sessionForMetadata),
		})
	} else {
		creds = credentials.NewStaticCredentials(a.AccessKey, a.AccessSecret, "")
	}
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(a.Region),
		Credentials: creds,
	})
	if err != nil {
		return err
	}
	a.awsSession = sess
	return nil
}

func certFingerprint(c []byte) ([]byte, error) {
	block, _ := pem.Decode(c)
	if block == nil {
		return nil, errors.New("no cert found (1)")
	}
	if block.Type != "CERTIFICATE" {
		return nil, errors.New("no cert found (2)")
	}
	h := sha256.Sum256(block.Bytes)
	return h[:], nil
}

func (a *acmObs) Import(cert *credhubCert) error {
	found := false
	for _, s := range a.Sources {
		if s == cert.Source {
			found = true
			break
		}
	}
	if !found {
		return nil // ignore, we don't want to store
	}

	a.awsMutex.Lock()
	defer a.awsMutex.Unlock()

	err := a.initAWSSessionAndCaches()
	if err != nil {
		return err
	}

	// Get the hostname from the path
	hn := hostFromPath(cert.path)

	// Find ARN
	arn, err := a.getARNforHost(hn)
	if err != nil {
		return err
	}

	// Fingerprint what we have
	currentFP, err := certFingerprint([]byte(cert.Certificate))
	if err != nil {
		return err
	}

	// Check if we can avoid writing a new cert
	if arn != "" {
		liveFP, err := a.getCurrentFingerprint(arn)
		if err != nil {
			return err
		}

		if bytes.Equal(currentFP, liveFP) {
			// no action required, exit early
			return nil
		}
	}

	// Finally, import the cert, update the fingerprint map
	log.Printf("Updating ACM cert for: %s in ARN: %s", hn, arn)
	ici := &acm.ImportCertificateInput{
		Certificate:      []byte(cert.Certificate),
		CertificateChain: []byte(cert.CA),
		PrivateKey:       []byte(cert.PrivateKey),
	}
	// if we have an ARN, then replace it
	if arn != "" {
		ici.CertificateArn = aws.String(arn)
	}
	ico, err := acm.New(a.awsSession).ImportCertificate(ici)
	if err != nil {
		return err
	}

	// update arn map
	a.arns[hn] = *ico.CertificateArn

	// update fp map
	a.fingerprints[*ico.CertificateArn] = currentFP

	return nil
}
