package makeinvoice

import (
	"testing"
)

func TestCommandoBackend(t *testing.T) {
	backend := CommandoParams{
		Rune:   "JcgqTJQm_Nnddp0R0vjS9sJJBHAar4UjT4EiMx-9Wto9OCZtZXRob2Q9aW52b2ljZQ==",
		Host:   "24.84.152.187:9735",
		NodeId: "03f3c108ccd536b8526841f0a5c58212bb9e6584a1eb493080e7c1cc34f82dad71",
	}
	params := Params{
		Backend:     backend,
		Msatoshi:    100000,
		Description: "TestCommandoBackend",
	}

	bolt11, err := MakeInvoice(params)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(bolt11)
}
