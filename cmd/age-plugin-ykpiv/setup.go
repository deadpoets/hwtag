package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/foxboron/age-plugin-tpm/ykpiv"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

// doSetup takes a YubiKey from any state to one unseal identity (design/16 B1):
//
//  1. reset the PIV application (all PIV keys erased; FIDO, OTP and the other
//     applications are untouched);
//  2. generate an attested P-256 key in slot, PIN and touch policy always;
//  3. set the operator's PIN and PUK, typed at the terminal;
//  4. replace the management key with 24 random bytes that are never shown or
//     stored, so no one can change PIV again without a reset (which destroys
//     the key);
//  5. check the result.
//
// Every secret is read from the terminal without echo, never argv or env.
func doSetup(serial uint32, slot piv.Slot, output string) error {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("--setup is interactive: run it in a terminal")
	}
	// Refuse an existing file now, but create it only once the card is done, so
	// an abandoned run leaves nothing behind.
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("%s already exists", output)
	}

	// Windows resets a card connection left idle for ~5 s, so read the card's
	// identity, ask every question, and only then reopen it and do all the card
	// work back to back.
	yk, err := ykpiv.OpenCard(serial)
	if err != nil {
		return err
	}
	serial, err = yk.Serial()
	v := yk.Version()
	yk.Close()
	if err != nil {
		return err
	}
	if v.Major < 5 || (v.Major == 5 && v.Minor < 4) {
		return fmt.Errorf("YubiKey firmware %d.%d.%d: need 5.4 or newer (AES management key, slot metadata)", v.Major, v.Minor, v.Patch)
	}

	fmt.Fprintf(os.Stderr, "\nThis RESETS the PIV application on YubiKey %d (firmware %d.%d.%d).\n", serial, v.Major, v.Minor, v.Patch)
	fmt.Fprintln(os.Stderr, "Every PIV key and certificate on it is erased. FIDO/WebAuthn, OTP and the other applications are not touched.")
	fmt.Fprintf(os.Stderr, "Type   reset %d   to continue: ", serial)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != fmt.Sprintf("reset %d", serial) {
		return errors.New("not confirmed; nothing changed")
	}

	pin, err := readNewSecret(fd, "PIN", nil)
	if err != nil {
		return err
	}
	puk, err := readNewSecret(fd, "PUK", func(s string) error {
		if s == pin {
			return errors.New("the PUK must differ from the PIN")
		}
		return nil
	})
	if err != nil {
		return err
	}

	if yk, err = ykpiv.OpenCard(serial); err != nil {
		return err
	}
	defer yk.Close()
	if err := yk.Reset(); err != nil {
		return fmt.Errorf("PIV reset: %v", err)
	}
	fmt.Fprintln(os.Stderr, "PIV reset: done (factory PIN, PUK and management key)")

	i, a, err := generateAttested(yk, serial, slot, piv.DefaultManagementKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "key: slot %x generated on the card, attestation verified (PIN always, touch always)\n", slot.Key)

	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		return fmt.Errorf("set PIN: %v", err)
	}
	fmt.Fprintln(os.Stderr, "PIN: set")
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		return fmt.Errorf("set PUK: %v", err)
	}
	fmt.Fprintln(os.Stderr, "PUK: set")

	mk := make([]byte, 24)
	if _, err := rand.Read(mk); err != nil {
		return err
	}
	err = yk.SetManagementKey(piv.DefaultManagementKey, mk)
	clear(mk)
	if err != nil {
		return fmt.Errorf("set management key: %v", err)
	}
	fmt.Fprintln(os.Stderr, "management key: replaced with a random AES-192 key, not shown or stored")

	// Check the result. None of these uses a PIN retry.
	probe := make([]byte, 24)
	rand.Read(probe)
	if err := yk.SetManagementKey(piv.DefaultManagementKey, probe); err == nil {
		return errors.New("CHECK FAILED: the factory management key still works")
	}
	clear(probe)
	if n, err := yk.Retries(); err != nil || n != 3 {
		return fmt.Errorf("CHECK FAILED: PIN retries %d (%v), want 3", n, err)
	}
	if err := yk.VerifyPIN(pin); err != nil {
		return fmt.Errorf("CHECK FAILED: the new PIN does not verify: %v", err)
	}
	ki, err := yk.KeyInfo(slot)
	if err != nil || ki.PINPolicy != piv.PINPolicyAlways || ki.TouchPolicy != piv.TouchPolicyAlways || ki.Origin != piv.OriginGenerated {
		return fmt.Errorf("CHECK FAILED: slot %x metadata %+v (%v)", slot.Key, ki, err)
	}
	fmt.Fprintln(os.Stderr, "check: factory management key rejected; PIN verifies; 3 PIN retries; slot policy PIN+touch always, generated on card")

	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := writeIdentity(f, i, a); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\nStore the PUK offline (with share C). It is the only way to unblock a PIN after 3 wrong tries.")
	fmt.Fprintln(os.Stderr, "Now UNPLUG and replug the YubiKey (clears the PIN login this setup left on the card).")
	return nil
}

// readNewSecret reads a new PIN or PUK twice without echo.
func readNewSecret(fd int, what string, extra func(string) error) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintf(os.Stderr, "New %s (6-8 characters, not shown): ", what)
		a, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		s := string(a)
		if err := validateSecret(what, s); err != nil {
			fmt.Fprintf(os.Stderr, "  %v; try again\n", err)
			continue
		}
		if extra != nil {
			if err := extra(s); err != nil {
				fmt.Fprintf(os.Stderr, "  %v; try again\n", err)
				continue
			}
		}
		fmt.Fprintf(os.Stderr, "Repeat the %s: ", what)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(b) != s {
			fmt.Fprintln(os.Stderr, "  they differ; try again")
			continue
		}
		return s, nil
	}
	return "", fmt.Errorf("no valid %s after 3 attempts", what)
}

// validateSecret enforces PIV's 6-8 byte range, printable ASCII, and refuses
// the factory values and trivial sequences.
func validateSecret(what, s string) error {
	if len(s) < 6 || len(s) > 8 {
		return errors.New("must be 6 to 8 characters")
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return errors.New("printable ASCII only, no spaces")
		}
	}
	if s == piv.DefaultPIN || s == piv.DefaultPUK {
		return errors.New("that is a factory default")
	}
	if strings.Count(s, s[:1]) == len(s) {
		return errors.New("all one character")
	}
	if strings.Contains("0123456789012345678", s) || strings.Contains("9876543210987654321", s) {
		return errors.New("a simple sequence")
	}
	return nil
}
