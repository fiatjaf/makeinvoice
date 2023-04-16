module github.com/fiatjaf/makeinvoice

go 1.16

require (
	github.com/fiatjaf/eclair-go v0.2.1
	github.com/fiatjaf/lightningd-gjson-rpc v1.6.2
	github.com/jb55/lnsocket/go v0.0.0-20220812055138-93307d1bfe4c
	github.com/lnpay/lnpay-go v1.1.0
	github.com/tidwall/gjson v1.8.1
	github.com/tidwall/sjson v1.1.7
)

replace launchpad.net/gocheck v0.0.0-20140225173054-000000000087 => github.com/essentialkaos/check v1.4.0

replace launchpad.net/xmlpath v0.0.0-20130614043138-000000000004 => github.com/go-xmlpath/xmlpath v0.0.0-20150820204837-860cbeca3ebc
