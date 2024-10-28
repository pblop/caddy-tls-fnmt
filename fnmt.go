package tls_client_auth_fnmt

import (
	"crypto/x509"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(FNMTClientAuth{})
}

type FNMTClientAuth struct {
	Names []string `json:"names,omitempty"`
	Dnis []string `json:"dnis,omitempty"`
	NameDnis []string `json:"namednis,omitempty"`
	logger *zap.Logger
}

func (FNMTClientAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_auth.verifier.fnmt",
		New: func() caddy.Module { return new(FNMTClientAuth) },
	}
}

func (f *FNMTClientAuth) Provision(ctx caddy.Context) error {
	f.logger = ctx.Logger()
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     fnmt {
// 			 names <full name1> <full name2>...
// 			 dnis <dni1> <dni2> ...
// 		}
//
func (f *FNMTClientAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "names":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			f.Names = d.RemainingArgs()
			if len(f.Names) == 0 {
				return d.ArgErr()
			}
		case "dnis":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			f.Dnis = d.RemainingArgs()
			if len(f.Dnis) == 0 {
				return d.ArgErr()
			}
		case "namednis":
			if d.CountRemainingArgs() == 0 {
				return d.ArgErr()
			}
			f.Dnis = d.RemainingArgs()
			if len(f.Dnis) == 0 {
				return d.ArgErr()
			}
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// OID for surname is 2.5.4.4 (https://www.alvestrand.no/objectid/2.5.4.4.html)
// OID for given name is 2.5.4.42 (https://www.alvestrand.no/objectid/2.5.4.42.html)
func GetFirstAndSurNames(cert *x509.Certificate) (string, string) {
	var surname, givenName string

	for _, name := range cert.Subject.Names {
		if name.Type.String() == "2.5.4.4" {
			surname = name.Value.(string)
		}
		if name.Type.String() == "2.5.4.42" {
			givenName = name.Value.(string)
		}
	}

	return givenName, surname
}

func (f FNMTClientAuth) VerifyClientCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no client certificate provided")
	}

	remoteFNMTCert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("error parsing the given certificate: %s", err.Error())
	}

	// The fields are:
	// - Country: ES (Spain)
	// - SerialNumber: IDCES-<DNI> (6 characters for IDCES- and 9 for the DNI number)
	//     IDC=Identity Document, ES=Spain
	// - Given Name: <FIRST NAME>
	// - Surname: <LAST NAMES>
	// - Common Name: <FIRST NAME> <LAST NAMES> - <DNI>

	// These checks might be unnecessary, but it's better to be safe than sorry.
	if !(len(remoteFNMTCert.Subject.Country) == 1 && remoteFNMTCert.Subject.Country[0] == "ES") {
		return fmt.Errorf("client fnmt certificate country failed validation")
	}
	if !(len(remoteFNMTCert.Subject.SerialNumber) == 15 && remoteFNMTCert.Subject.SerialNumber[:6] == "IDCES-") {
		return fmt.Errorf("client fnmt certificate serial number failed validation")
	}
	// We could even verify the DNI is real. But I don't think the FNMT will issue a certificate to
	// an invalid DNI.

	// The DNI is the serial number, ommitting the IDCES- prefix.
	var dni string = remoteFNMTCert.Subject.SerialNumber[6:]
	var commonName string = remoteFNMTCert.Subject.CommonName
	var givenName, surname = GetFirstAndSurNames(remoteFNMTCert)
	// The full name is the given name and the surname.
	var name string = givenName + " " + surname

	// Check if the certificate subject names match the given names.
	for _, n := range f.Names {
		if n == name {
			f.logger.Info("client fnmt certificate full name matched", zap.String("name", name))
			return nil
		}
	}
	for _, d := range f.Dnis {
		if d == dni {
			f.logger.Info("client fnmt certificate dni matched", zap.String("dni", dni))
			return nil
		}
	}
	for _, namedni := range f.NameDnis {
		if namedni == commonName {
			f.logger.Info("client fnmt certificate full name and dni matched", zap.String("nameDni", namedni))
			return nil
		}
	}

	return fmt.Errorf("client fnmt certificate failed validation")
}

var _ caddyfile.Unmarshaler = (*FNMTClientAuth)(nil)
