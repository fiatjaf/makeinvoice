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
	"net/url"
	"strconv"
	"strings"
	"time"

	lightning "github.com/fiatjaf/lightningd-gjson-rpc"
	"github.com/lnpay/lnpay-go"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var TorProxyURL = "socks5://127.0.0.1:9050"

type Params struct {
	Backend         BackendParams
	Msatoshi        int64
	Description     string
	DescriptionHash []byte

	Label string // only used for c-lightning
}

type SparkoParams struct {
	Cert string
	Host string
	Key  string
}

func (l SparkoParams) getCert() string { return l.Cert }
func (l SparkoParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNDParams struct {
	Cert     string
	Host     string
	Macaroon string
}

func (l LNDParams) getCert() string { return l.Cert }
func (l LNDParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNBitsParams struct {
	Cert string
	Host string
	Key  string
}

func (l LNBitsParams) getCert() string { return l.Cert }
func (l LNBitsParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type LNPayParams struct {
	PublicAccessKey  string
	WalletInvoiceKey string
}

func (l LNPayParams) getCert() string { return "" }
func (l LNPayParams) isTor() bool     { return false }

type BackendParams interface {
	getCert() string
	isTor() bool
}

func MakeInvoice(params Params) (bolt11 string, err error) {
	defer func(prevTransport http.RoundTripper) {
		http.DefaultClient.Transport = prevTransport
	}(http.DefaultClient.Transport)

	specialTransport := &http.Transport{}

	// use a cert or skip TLS verification?
	if params.Backend.getCert() != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(params.Backend.getCert()))
		specialTransport.TLSClientConfig = &tls.Config{RootCAs: caCertPool}
	} else {
		specialTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// use a tor proxy?
	if params.Backend.isTor() {
		torURL, _ := url.Parse(TorProxyURL)
		specialTransport.Proxy = http.ProxyURL(torURL)
	}

	http.DefaultClient.Transport = specialTransport

	// set a timeout
	http.DefaultClient.Timeout = 15 * time.Second

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

		label := params.Label
		if label == "" {
			label = "makeinvoice/" + strconv.FormatInt(time.Now().Unix(), 16)
		}

		inv, err := spark.Call(method, params.Msatoshi, label, desc)
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

		// macaroon must be hex, so if it is on base64 we adjust that
		if b, err := base64.StdEncoding.DecodeString(backend.Macaroon); err == nil {
			backend.Macaroon = hex.EncodeToString(b)
		}

		req.Header.Set("Grpc-Metadata-macaroon", backend.Macaroon)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(resp.Body)
			text := string(body)
			if len(text) > 300 {
				text = text[:300]
			}
			return "", fmt.Errorf("call to lnd failed (%d): %s", resp.StatusCode, text)
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return gjson.ParseBytes(b).Get("payment_request").String(), nil

	case LNBitsParams:
		body, _ := sjson.Set("{}", "amount", params.Msatoshi/1000)
		body, _ = sjson.Set(body, "out", false)
		if params.Description == "" {
			body, _ = sjson.Set(body, "memo", "MakeInvoice")
		} else {
			body, _ = sjson.Set(body, "memo", params.Description)
		}

		req, err := http.NewRequest("POST",
			backend.Host+"/api/v1/payments",
			bytes.NewBufferString(body),
		)
		if err != nil {
			return "", err
		}

		req.Header.Set("X-Api-Key", backend.Key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			body, _ := ioutil.ReadAll(resp.Body)
			text := string(body)
			if len(text) > 300 {
				text = text[:300]
			}
			return "", fmt.Errorf("call to lnbits failed (%d): %s", resp.StatusCode, text)
		}

		defer resp.Body.Close()
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		return gjson.ParseBytes(b).Get("payment_request").String(), nil
	case LNPayParams:
		client := lnpay.NewClient(backend.PublicAccessKey)
		wallet := client.Wallet(backend.WalletInvoiceKey)
		lntx, err := wallet.Invoice(lnpay.InvoiceParams{
			NumSatoshis:     params.Msatoshi / 1000,
			DescriptionHash: hexh,
		})
		if err != nil {
			return "", fmt.Errorf("error creating invoice on lnpay: %w", err)
		}

		return lntx.PaymentRequest, nil
	}

	return "", errors.New("missing backend params")
}
