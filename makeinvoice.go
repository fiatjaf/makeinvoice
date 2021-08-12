package makeinvoice

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	lightning "github.com/fiatjaf/lightningd-gjson-rpc"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type Params struct {
	Backend         BackendParams
	Msatoshi        int64
	Description     string
	DescriptionHash []byte
}

type SparkoParams struct {
	Cert string
	Host string
	Key  string
}

func (l SparkoParams) GetCert() string { return l.Cert }

type LNDParams struct {
	Cert     string
	Host     string
	Macaroon string
}

func (l LNDParams) GetCert() string { return l.Cert }

type LNBitsParams struct {
	Cert string
	Host string
	Key  string
}

func (l LNBitsParams) GetCert() string { return l.Cert }

type BackendParams interface {
	GetCert() string
}

func MakeInvoice(params Params) (bolt11 string, err error) {
	defer func(prevTransport http.RoundTripper) {
		http.DefaultClient.Transport = prevTransport
	}(http.DefaultClient.Transport)

	// use a cert or skip TLS verification?
	if params.Backend.GetCert() != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(params.Backend.GetCert()))
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		}
	} else {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// description hash?
	var hexh, b64h string
	if params.DescriptionHash != nil {
		hexh = hex.EncodeToString(params.DescriptionHash)
		b64h = base64.StdEncoding.EncodeToString(params.DescriptionHash)
	}

	switch backend := params.Backend.(type) {
	case SparkoParams:
		spark := &lightning.Client{
			SparkURL:    backend.Host,
			SparkToken:  backend.Key,
			CallTimeout: time.Second * 3,
		}

		var method, desc string
		if params.DescriptionHash == nil {
			method = "invoice"
			desc = params.Description
		} else {
			method = "invoicewithdescriptionhash"
			desc = hexh
		}

		inv, err := spark.Call(method, params.Msatoshi,
			"lightningaddr/"+strconv.FormatInt(time.Now().Unix(), 16), desc)
		if err != nil {
			return "", fmt.Errorf(method+" call failed: %w", err)
		}
		return inv.Get("bolt11").String(), nil

	case LNDParams:
		body, _ := sjson.Set("{}", "value_msat", params.Msatoshi)

		if params.DescriptionHash == nil {
			body, _ = sjson.Set(body, "memo", params.Description)
		} else {
			body, _ = sjson.Set(body, "description_hash", b64h)
		}

		req, err := http.NewRequest("POST",
			backend.Host+"/v1/invoices",
			bytes.NewBufferString(body),
		)
		if err != nil {
			return "", err
		}

		req.Header.Set("Grpc-Metadata-macaroon", backend.Macaroon)
		resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode >= 300 {
			return "", errors.New("call to lnd failed")
		}

		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return gjson.ParseBytes(b).Get("payment_request").String(), nil

	case LNBitsParams:
		body, _ := sjson.Set("{}", "amount", params.Msatoshi/1000)
		body, _ = sjson.Set(body, "out", false)

		if params.DescriptionHash == nil {
			body, _ = sjson.Set(body, "memo", params.Description)
		} else {
			body, _ = sjson.Set(body, "description_hash", b64h)
		}

		req, err := http.NewRequest("POST",
			backend.Host+"/v1/invoices",
			bytes.NewBufferString(body),
		)
		if err != nil {
			return "", err
		}

		req.Header.Set("X-Api-Key", backend.Key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
		if err != nil {
			return "", err
		}
		if resp.StatusCode >= 300 {
			return "", errors.New("call to lnbits failed")
		}

		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return gjson.ParseBytes(b).Get("payment_request").String(), nil
	}

	return "", errors.New("missing backend params")
}
