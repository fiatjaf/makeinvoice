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

	"github.com/fiatjaf/eclair-go"
	lightning "github.com/fiatjaf/lightningd-gjson-rpc"
	"github.com/lnpay/lnpay-go"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var TorProxyURL = "socks5://127.0.0.1:9050"
var Client = &http.Client{
	Timeout: 10 * time.Second,
}

type Params struct {
	Backend         BackendParams
	Msatoshi        int64
	Description     string
	DescriptionHash []byte

	Label    string // only used for c-lightning
	Username string // only used for strike
	Currency string // only used for strike
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

type EclairParams struct {
	Host     string
	Password string
	Cert     string
}

func (l EclairParams) getCert() string { return l.Cert }
func (l EclairParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type StrikeParams struct {
	Cert string
	Host string
	Key  string
}

func (l StrikeParams) getCert() string { return l.Cert }
func (l StrikeParams) isTor() bool     { return strings.Index(l.Host, ".onion") != -1 }

type BackendParams interface {
	getCert() string
	isTor() bool
}

func MakeInvoice(params Params) (bolt11 string, err error) {
	defer func(prevTransport http.RoundTripper) {
		Client.Transport = prevTransport
	}(Client.Transport)

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

	Client.Transport = specialTransport

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
		resp, err := Client.Do(req)
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

		if params.DescriptionHash == nil {
			if params.Description == "" {
				body, _ = sjson.Set(body, "memo", "created by makeinvoice")
			} else {
				body, _ = sjson.Set(body, "memo", params.Description)
			}
		} else {
			body, _ = sjson.Set(body, "description_hash", hexh)
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
		resp, err := Client.Do(req)
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
			Memo:            params.Description,
			DescriptionHash: hexh,
		})
		if err != nil {
			return "", fmt.Errorf("error creating invoice on lnpay: %w", err)
		}

		return lntx.PaymentRequest, nil
	case EclairParams:
		client := eclair.Client{Host: backend.Host, Password: backend.Password}
		eclairParams := eclair.Params{"amountMsat": params.Msatoshi}

		if 0 < len(params.DescriptionHash) {
			eclairParams["descriptionHash"] = hexh
		} else {
			eclairParams["description"] = params.Description
		}

		inv, err := client.Call("createinvoice", eclairParams)
		if err != nil {
			return "", fmt.Errorf("error creating invoice on eclair: %w", err)
		}

		return inv.Get("serialized").String(), nil
	case StrikeParams:
		url := "https://api.strike.me/v1/invoices/handle/" + params.Username
		method := "POST"
		invoiceDescription := "created by makeinvoice"
		if params.Description != "" {
			invoiceDescription = params.Description
		}
		btcValue := float32(params.Msatoshi) / 100000000000
		payload := strings.NewReader(fmt.Sprintf(`{
		"description": "%s",
		"amount": {
			"currency": "%s",
			"amount": "%.8f"
		}
		}`, invoiceDescription, params.Currency, btcValue))
		// TODO: BTC currency does not seem to be supported at the moment
		// Currently the currency needs to be the user's base currency (USD for the US, USDT for El Sal and Argentina).
		// However, we're going to enable BTC invoices in the coming weeks.

		client := &http.Client{}
		req, err := http.NewRequest(method, url, payload)

		if err != nil {
			fmt.Println(err)
			return "", err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", "Bearer "+backend.Key)

		res, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return "", err
		}

		invoiceId := gjson.ParseBytes(body).Get("invoiceId").String()

		// got strike invoice - get actual LN invoice now. sigh.
		url = "https://api.strike.me/v1/invoices/" + invoiceId + "/quote"
		req, err = http.NewRequest(method, url, payload)

		if err != nil {
			fmt.Println(err)
			return "", err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", "Bearer "+backend.Key)

		res, err = client.Do(req)
		if err != nil {
			fmt.Println(err)
			return "", err
		}
		defer res.Body.Close()

		body, err = ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println(err)
			return "", err
		}

		lnInvoice := gjson.ParseBytes(body).Get("lnInvoice").String()
		// println("lnInvoice ", lnInvoice)

		return lnInvoice, nil

	}

	return "", errors.New("missing backend params")
}
