package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"log"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type certObserver interface {
	CertsAreUpdated(certs []*credhubCert) error
}

type bucket struct {
	Region       string `yaml:"region"`
	Bucket       string `yaml:"bucket"`
	Object       string `yaml:"object"`
	AccessKey    string `yaml:"access_key"`
	AccessSecret string `yaml:"access_secret"`

	awsMutex   sync.Mutex
	awsSession *session.Session

	lastSuccessfulWritten []byte
}

func stringval(s *string) string {
	if s == nil {
		return "n/a"
	}
	return *s
}

func (b *bucket) Put(data []byte) error {
	b.awsMutex.Lock()
	defer b.awsMutex.Unlock()

	if bytes.Equal(data, b.lastSuccessfulWritten) {
		return nil
	}

	if b.awsSession == nil {
		var creds *credentials.Credentials
		if b.AccessKey == "" { // if not specified, assume EC2RoleProvider
			creds = credentials.NewCredentials(&ec2rolecreds.EC2RoleProvider{})
		} else {
			creds = credentials.NewStaticCredentials(b.AccessKey, b.AccessSecret, "")
		}
		sess, err := session.NewSession(&aws.Config{
			Region:      aws.String(b.Region),
			Credentials: creds,
		})
		if err != nil {
			return err
		}
		b.awsSession = sess
	}

	result, err := s3manager.NewUploader(b.awsSession).Upload(&s3manager.UploadInput{
		Bucket:               aws.String(b.Bucket),
		Key:                  aws.String(b.Object),
		Body:                 bytes.NewReader(data),
		ServerSideEncryption: aws.String("AES256"),
	})
	if err != nil {
		return err
	}

	b.lastSuccessfulWritten = data

	log.Printf("Cert tarball successfully uploaded to: %s (version %s)\n", result.Location, stringval(result.VersionID))

	return nil
}

type outputObserver struct {
	S3 []*bucket `yaml:"s3"`

	ssOracle shouldShipOracle
}

func (n *outputObserver) Init(ssOracle shouldShipOracle) error {
	n.ssOracle = ssOracle
	return nil
}

func (n *outputObserver) createTarball(certs []*credhubCert) ([]byte, error) {
	buffer := &bytes.Buffer{}
	gzipWriter := gzip.NewWriter(buffer)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, cert := range certs {
		hn := hostFromPath(cert.path)
		if !n.ssOracle.ShipToProxy(hn) {
			// skip
			continue
		}
		if strings.TrimSpace(cert.Certificate) == "" {
			// not issued yet, skip
			continue
		}

		he := hex.EncodeToString([]byte(hn))

		certBytes := []byte(strings.Join([]string{
			strings.TrimSpace(cert.PrivateKey),
			strings.TrimSpace(cert.Certificate),
			strings.TrimSpace(cert.CA),
			"", // so that we have a trailing new line
		}, "\n"))

		err := tarWriter.WriteHeader(&tar.Header{
			Name:     he + ".crt",
			Mode:     0600,
			Size:     int64(len(certBytes)),
			Typeflag: tar.TypeReg,
			ModTime:  cert.dateCreated,
		})
		if err != nil {
			return nil, err
		}
		_, err = tarWriter.Write(certBytes)
		if err != nil {
			return nil, err
		}
	}

	err := tarWriter.Close()
	if err != nil {
		return nil, err
	}
	err = gzipWriter.Close()
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func (n *outputObserver) CertsAreUpdated(certs []*credhubCert) error {
	tb, err := n.createTarball(certs)
	if err != nil {
		return err
	}

	for _, bucket := range n.S3 {
		err = bucket.Put(tb)
		if err != nil {
			return err
		}
	}

	return nil
}
