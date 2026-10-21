// Command age-plugin-ykpiv is an age plugin for P-256 keys in a YubiKey PIV
// slot, decrypting age1tag1... (p256tag) files. See package ykpiv.
//
//	age-plugin-ykpiv --generate --slot 82 -o identity.txt   # new key, touch always
//	age-plugin-ykpiv -y identity.txt                        # print the recipient
//	age -r age1tag1... -o x.age x                           # encrypt: stock age
//	age -d -i identity.txt x.age                            # decrypt: PIN + touch
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	page "filippo.io/age/plugin"
	"github.com/deadpoets/hwtag/ykpiv"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

func main() {
	p, err := page.New(ykpiv.Name)
	if err != nil {
		fatal(err)
	}
	p.RegisterFlags(nil)
	generate := flag.Bool("generate", false, "generate a new key on the YubiKey")
	setup := flag.Bool("setup", false, "B1: reset PIV, generate the unseal key, set PIN and PUK, lock the management key (interactive)")
	slotFlag := flag.String("slot", "82", "PIV slot, hex: 9d or 82-95")
	serial := flag.Uint("serial", 0, "YubiKey serial (required when more than one is present)")
	defaultMgmt := flag.Bool("default-mgmt-key", false, "use the factory management key (fresh keys only; B1 replaces it)")
	replace := flag.Bool("replace", false, "overwrite a key already in the slot (destroys it)")
	output := flag.String("o", "", "write the identity to this new file")
	convert := flag.String("y", "", "print the recipient for this identity file")
	flag.Parse()

	if flag.Lookup("age-plugin").Value.String() != "" {
		p.HandleIdentity(func(data []byte) (age.Identity, error) {
			i, err := ykpiv.Unmarshal(data)
			if err != nil {
				return nil, err
			}
			i.PIN = func() (string, error) {
				return p.RequestValue(fmt.Sprintf("PIV PIN for YubiKey %d:", i.Serial), true)
			}
			i.Notify = p.DisplayMessage
			return i, nil
		})
		p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
			i, err := ykpiv.Unmarshal(data)
			if err != nil {
				return nil, err
			}
			return i.Recipient()
		})
		os.Exit(p.Main())
	}

	switch {
	case *setup:
		key, err := strconv.ParseUint(*slotFlag, 16, 8)
		if err != nil {
			fatal(fmt.Errorf("--slot: %v", err))
		}
		slot, err := ykpiv.SlotFor(uint32(key))
		if err != nil {
			fatal(err)
		}
		if *output == "" {
			fatal(errors.New("--setup needs -o FILE"))
		}
		fatal(doSetup(uint32(*serial), slot, *output))
	case *generate:
		key, err := strconv.ParseUint(*slotFlag, 16, 8)
		if err != nil {
			fatal(fmt.Errorf("--slot: %v", err))
		}
		slot, err := ykpiv.SlotFor(uint32(key))
		if err != nil {
			fatal(err)
		}
		if *output == "" {
			fatal(errors.New("--generate needs -o FILE"))
		}
		fatal(doGenerate(uint32(*serial), slot, *defaultMgmt, *replace, *output))
	case *convert != "":
		i, err := readIdentity(*convert)
		if err != nil {
			fatal(err)
		}
		r, err := i.Recipient()
		if err != nil {
			fatal(err)
		}
		fmt.Println(r.String())
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fatal(err error) {
	if err == nil {
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "age-plugin-ykpiv: %v\n", err)
	os.Exit(1)
}

func readIdentity(path string) (*ykpiv.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, data, err := page.ParseIdentity(line)
		if err != nil {
			return nil, err
		}
		if name != ykpiv.Name {
			return nil, fmt.Errorf("identity is for plugin %q", name)
		}
		return ykpiv.Unmarshal(data)
	}
	return nil, errors.New("no identity in file")
}

// managementKey returns the factory key only when asked for explicitly,
// otherwise reads it from the terminal without echo. It is never taken from
// argv or the environment.
func managementKey(useDefault bool) ([]byte, error) {
	if useDefault {
		return piv.DefaultManagementKey, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("the management key is read from a terminal; none attached")
	}
	fmt.Fprint(os.Stderr, "PIV management key (hex): ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(b)))
}

func doGenerate(serial uint32, slot piv.Slot, useDefault, replace bool, output string) error {
	// Refuse an existing file now, but create it only once the card is done,
	// so an abandoned run leaves nothing behind (as --setup does).
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("%s already exists", output)
	}

	yk, err := ykpiv.OpenCard(serial)
	if err != nil {
		return err
	}
	defer yk.Close()
	if serial == 0 {
		if serial, err = yk.Serial(); err != nil {
			return err
		}
	}
	// Never overwrite a slot: if the card reports metadata, something is there.
	if ki, err := yk.KeyInfo(slot); err == nil && ki.PublicKey != nil && !replace {
		return fmt.Errorf("slot %x on YubiKey %d already holds a key; refusing to overwrite", slot.Key, serial)
	}
	mk, err := managementKey(useDefault)
	if err != nil {
		return err
	}
	i, a, err := generateAttested(yk, serial, slot, mk)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := writeIdentity(f, i, a); err != nil {
		return err
	}
	// piv-go disconnects with SCARD_LEAVE_CARD, so the management-key login
	// outlives this process until the card is reset.
	fmt.Fprintln(os.Stderr, "now UNPLUG and replug the YubiKey: that clears the management-key login from the card")
	return nil
}

// generateAttested makes a P-256 key in slot with PIN and touch policy always,
// and proves it was generated on this card with those policies: the slot's
// attestation certificate must chain to Yubico's roots and carry the key now
// in the slot.
func generateAttested(yk *piv.YubiKey, serial uint32, slot piv.Slot, mk []byte) (*ykpiv.Identity, *piv.Attestation, error) {
	if _, err := yk.GenerateKey(mk, slot, piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}); err != nil {
		return nil, nil, err
	}
	ac, err := yk.AttestationCertificate()
	if err != nil {
		return nil, nil, fmt.Errorf("attestation certificate: %v", err)
	}
	sc, err := yk.Attest(slot)
	if err != nil {
		return nil, nil, fmt.Errorf("attest slot: %v", err)
	}
	a, err := piv.Verify(ac, sc)
	if err != nil {
		return nil, nil, fmt.Errorf("attestation does not verify: %v", err)
	}
	if a.Serial != serial || a.TouchPolicy != piv.TouchPolicyAlways || a.PINPolicy != piv.PINPolicyAlways {
		return nil, nil, fmt.Errorf("attestation mismatch: serial %d, touch %v, pin %v", a.Serial, a.TouchPolicy, a.PINPolicy)
	}
	ki, err := yk.KeyInfo(slot)
	if err != nil {
		return nil, nil, err
	}
	if kp := marshalPub(ki.PublicKey); len(kp) == 0 || !bytes.Equal(kp, marshalPub(sc.PublicKey)) {
		return nil, nil, errors.New("attested key differs from the slot's key")
	}
	pub, err := ecdsaToECDH(sc.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return &ykpiv.Identity{Serial: serial, Slot: slot, Pub: pub}, a, nil
}

// writeIdentity writes the identity file and prints the recipient on stdout.
func writeIdentity(f *os.File, i *ykpiv.Identity, a *piv.Attestation) error {
	data, err := i.Marshal()
	if err != nil {
		return err
	}
	r, err := i.Recipient()
	if err != nil {
		return err
	}
	fmt.Fprintf(f, "# created: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "# yubikey: serial %d, firmware %d.%d.%d, slot %x\n", i.Serial, a.Version.Major, a.Version.Minor, a.Version.Patch, i.Slot.Key)
	fmt.Fprintf(f, "# policy: pin always, touch always (attested by Yubico)\n")
	fmt.Fprintf(f, "# recipient: %s\n", r.String())
	if _, err := fmt.Fprintf(f, "%s\n", page.EncodeIdentity(ykpiv.Name, data)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "generated: YubiKey %d slot %x, attested (firmware %d.%d.%d)\n", i.Serial, i.Slot.Key, a.Version.Major, a.Version.Minor, a.Version.Patch)
	fmt.Println(r.String())
	return nil
}
