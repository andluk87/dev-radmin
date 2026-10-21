// native-check runs synthetic interoperability checks with the original x86 helper.
// It does not start a VPN, access the network, or change the installed application.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"dev-radmin/internal/bootstrap"
	"dev-radmin/internal/channel"
	"dev-radmin/internal/srp"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const helperHash = "d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4"
const fixturePassword = "research-only-password"

type native struct {
	dll        *syscall.DLL
	procs      map[string]*syscall.Proc
	copyMemory *syscall.LazyProc
}

func pinned(b []byte) (uintptr, func()) {
	if len(b) == 0 {
		return 0, func() {}
	}
	p := new(runtime.Pinner)
	p.Pin(&b[0])
	return uintptr(unsafe.Pointer(&b[0])), func() { p.Unpin(); runtime.KeepAlive(b) }
}
func (n *native) call(name string, args ...uintptr) uintptr {
	v, _, _ := n.procs[name].Call(args...)
	return v
}
func (n *native) copyOutput(ptr uint32, size uint32) []byte {
	result := make([]byte, int(size))
	if size == 0 {
		return result
	}
	destination, release := pinned(result)
	defer release()
	n.copyMemory.Call(destination, uintptr(ptr), uintptr(size))
	return result
}
func (n *native) buffer(name string, handle uintptr, input []byte, step, session bool) ([]byte, bool, error) {
	in, unpin := pinned(input)
	defer unpin()
	out := make([]byte, 16)
	p, release := pinned(out)
	defer release()
	args := []uintptr{handle, p, p + 4}
	if step {
		args = []uintptr{handle, in, uintptr(len(input)), p, p + 4, p + 8}
		if !session {
			args = append(args, p+12)
		}
	}
	ok := n.call(name, args...)
	ptr, size := binary.LittleEndian.Uint32(out), binary.LittleEndian.Uint32(out[4:])
	if ptr != 0 {
		defer n.call("SHelper_FreeBuffer", uintptr(ptr))
	}
	if ok != 1 || (!session && step && binary.LittleEndian.Uint32(out[12:]) != 0) {
		return nil, false, fmt.Errorf("%s rejected operation", name)
	}
	if size > 4096 || (size > 0 && ptr == 0) {
		return nil, false, errors.New("invalid native output size")
	}
	var result []byte
	if size > 0 {
		result = n.copyOutput(ptr, size)
	}
	return result, binary.LittleEndian.Uint32(out[8:]) == 1, nil
}
func (n *native) transform(handle uintptr, input []byte, encrypt bool) ([]byte, error) {
	name := "SHelper_CChannel_DecryptBuffer"
	if encrypt {
		name = "SHelper_CChannel_EncryptBuffer"
	}
	in, unpin := pinned(input)
	defer unpin()
	out := make([]byte, 8)
	p, release := pinned(out)
	defer release()
	ok := n.call(name, handle, in, uintptr(len(input)), p, p+4)
	ptr, size := binary.LittleEndian.Uint32(out), binary.LittleEndian.Uint32(out[4:])
	if ptr != 0 {
		defer n.call("SHelper_FreeBuffer", uintptr(ptr))
	}
	if ok != 1 || size == 0 || size > 4096 || ptr == 0 {
		return nil, errors.New("native channel rejected record")
	}
	return n.copyOutput(ptr, size), nil
}
func load(path string) (*native, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute DLL path required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read helper DLL")
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != helperHash {
		return nil, errors.New("unsupported helper DLL SHA-256")
	}
	dll, err := syscall.LoadDLL(path)
	if err != nil {
		return nil, errors.New("Windows could not load the original x86 helper DLL")
	}
	n := &native{dll: dll, procs: make(map[string]*syscall.Proc), copyMemory: syscall.NewLazyDLL("kernel32.dll").NewProc("RtlMoveMemory")}
	if err := n.copyMemory.Find(); err != nil {
		dll.Release()
		return nil, errors.New("Windows memory-copy API unavailable")
	}
	names := []string{"SHelper_Init", "SHelper_GetNetworkProtocolVersion", "SHelper_CreateClient", "SHelper_Delete", "SHelper_GetNextBuffer", "SHelper_GetKey", "SHelper_FreeBuffer", "SHelper_RSession_CreateClient", "SHelper_RSession_Delete", "SHelper_RSession_GetNextBuffer", "SHelper_RSession_GetKey", "SHelper_CChannel_CreateClient", "SHelper_CChannel_Delete", "SHelper_CChannel_EncryptBuffer", "SHelper_CChannel_DecryptBuffer", "SHelper_CChannel_SetKeyEnc", "SHelper_CChannel_SetKeyDec"}
	for _, name := range names {
		proc, e := dll.FindProc(name)
		if e != nil {
			dll.Release()
			return nil, fmt.Errorf("missing native export %s", name)
		}
		n.procs[name] = proc
	}
	if n.call("SHelper_Init") != 1 || n.call("SHelper_GetNetworkProtocolVersion") != 3 {
		dll.Release()
		return nil, errors.New("original helper initialization or protocol check failed")
	}
	return n, nil
}

func check(n *native, private *rsa.PrivateKey, caseName string) error {
	modulus := private.N.Bytes()
	exponent := []byte{1, 0, 1}
	mp, mu := pinned(modulus)
	defer mu()
	ep, eu := pinned(exponent)
	defer eu()
	rsession := n.call("SHelper_RSession_CreateClient", 3, 42, 7, mp, uintptr(len(modulus)), ep, uintptr(len(exponent)))
	if rsession == 0 {
		return errors.New("native RSA context creation failed")
	}
	defer n.call("SHelper_RSession_Delete", rsession)
	request, done, err := n.buffer("SHelper_RSession_GetNextBuffer", rsession, nil, true, true)
	if err != nil || done || len(request) != 192 {
		return errors.New("native RSA request failed")
	}
	metadata, material, err := bootstrap.Decode(private, request)
	if err != nil || metadata != [3]uint32{3, 42, 7} {
		return errors.New("Go rejected native RSA request")
	}
	defer func() {
		for i := range material {
			material[i] = 0
		}
	}()
	reply := make([]byte, 4)
	binary.LittleEndian.PutUint32(reply, 3)
	output, done, err := n.buffer("SHelper_RSession_GetNextBuffer", rsession, reply, true, true)
	if err != nil || !done || len(output) != 0 {
		return errors.New("native RSA completion failed")
	}
	nativeMaterial, _, err := n.buffer("SHelper_RSession_GetKey", rsession, nil, false, true)
	if err != nil || !bytes.Equal(nativeMaterial, material) {
		return errors.New("RSA key material differs")
	}
	for i := range nativeMaterial {
		nativeMaterial[i] = 0
	}
	key, ku := pinned(material[:32])
	defer ku()
	nativeChannel := n.call("SHelper_CChannel_CreateClient", key, 32, key, 32)
	if nativeChannel == 0 {
		return errors.New("native channel creation failed")
	}
	defer n.call("SHelper_CChannel_Delete", nativeChannel)
	goChannel, err := channel.New(material[:32], material[:32])
	if err != nil {
		return err
	}
	salt := make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	record, err := srp.Derive(42, []byte(fixturePassword), salt)
	if err != nil {
		return err
	}
	server, err := srp.NewServer(record, nil)
	if err != nil {
		return err
	}
	password := []byte(fixturePassword)
	if caseName == "wrong-password" {
		password = []byte("wrong-research-password")
	}
	pp, pu := pinned(password)
	defer pu()
	client := n.call("SHelper_CreateClient", 42, 0, pp, uintptr(len(password)))
	if client == 0 {
		return errors.New("native SRP creation failed")
	}
	defer n.call("SHelper_Delete", client)
	incoming := []byte(nil)
	for turn := 0; turn < 3; turn++ {
		plain, complete, e := n.buffer("SHelper_GetNextBuffer", client, incoming, true, false)
		if e != nil || complete {
			return errors.New("unexpected native SRP state")
		}
		if caseName == "tampered-proof" && turn == 2 {
			plain[len(plain)-1] ^= 1
		}
		encrypted, e := n.transform(nativeChannel, plain, true)
		if e != nil {
			return e
		}
		if caseName == "tampered-channel" && turn == 2 {
			encrypted[0] ^= 1
		}
		decoded, e := goChannel.Decrypt(encrypted)
		if e != nil {
			if turn == 2 && caseName == "tampered-channel" && errors.Is(e, channel.ErrRecord) {
				return nil
			}
			return errors.New("unexpected Go channel rejection")
		}
		response, complete, e := server.Step(decoded)
		if e != nil {
			if turn == 2 && (caseName == "wrong-password" || caseName == "tampered-proof") && errors.Is(e, srp.ErrAuthentication) {
				return nil
			}
			return errors.New("unexpected Go SRP rejection")
		}
		if complete != (turn == 2) {
			return errors.New("unexpected Go SRP completion state")
		}
		encrypted, e = goChannel.Encrypt(response)
		if e != nil {
			return e
		}
		incoming, e = n.transform(nativeChannel, encrypted, false)
		if e != nil {
			return e
		}
	}
	if caseName != "correct" {
		return errors.New("invalid credentials or corruption were accepted")
	}
	output, done, err = n.buffer("SHelper_GetNextBuffer", client, incoming, true, false)
	if err != nil || !done || len(output) != 0 {
		return errors.New("native SRP proof verification failed")
	}
	nativeKey, _, err := n.buffer("SHelper_GetKey", client, nil, false, false)
	if err != nil {
		return err
	}
	defer func() {
		for i := range nativeKey {
			nativeKey[i] = 0
		}
	}()
	goKey, err := server.SessionKey()
	if err != nil {
		return err
	}
	defer func() {
		for i := range goKey {
			goKey[i] = 0
		}
	}()
	if len(goKey) != 40 || !bytes.Equal(nativeKey, goKey) {
		return errors.New("SRP session keys differ")
	}
	kp, kRelease := pinned(nativeKey[:32])
	defer kRelease()
	if n.call("SHelper_CChannel_SetKeyEnc", nativeChannel, kp, 32) != 1 || n.call("SHelper_CChannel_SetKeyDec", nativeChannel, kp, 32) != 1 {
		return errors.New("native rekey failed")
	}
	if err = goChannel.Rekey(goKey[:32], goKey[:32]); err != nil {
		return err
	}
	// Synthetic application data verifies that IVs survive the SRP-to-session rekey.
	for _, payload := range [][]byte{[]byte("synthetic post-auth client payload"), bytes.Repeat([]byte{0xa5}, 289)} {
		enc, e := n.transform(nativeChannel, payload, true)
		if e != nil {
			return e
		}
		dec, e := goChannel.Decrypt(enc)
		if e != nil || !bytes.Equal(dec, payload) {
			return errors.New("client-to-Go rekey continuity failed")
		}
		enc, e = goChannel.Encrypt(payload)
		if e != nil {
			return e
		}
		dec, e = n.transform(nativeChannel, enc, false)
		if e != nil || !bytes.Equal(dec, payload) {
			return errors.New("Go-to-client rekey continuity failed")
		}
	}
	return nil
}

type caseResult struct {
	Case   string `json:"case"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitempty"`
}
type report struct {
	Schema    int          `json:"schema_version"`
	Platform  string       `json:"platform"`
	DLLHash   string       `json:"dll_sha256"`
	Synthetic bool         `json:"synthetic_only"`
	VPNReady  bool         `json:"vpn_ready"`
	Passed    bool         `json:"passed"`
	Cases     []caseResult `json:"cases"`
	Error     string       `json:"error,omitempty"`
}

func run() int {
	path := flag.String("dll", "", "absolute path to original x86 shelper.dll")
	out := flag.String("output", "native-check.json", "NEW JSON report; no keys, passwords or account data")
	flag.Parse()
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create a new report file")
		return 1
	}
	defer f.Close()
	result := report{Schema: 1, Platform: "windows/386", DLLHash: helperHash, Synthetic: true}
	n, err := load(*path)
	if err == nil {
		defer n.dll.Release()
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 1536)
		if err == nil {
			result.Passed = true
			for _, name := range []string{"correct", "wrong-password", "tampered-proof", "tampered-channel"} {
				e := check(n, key, name)
				item := caseResult{Case: name, Passed: e == nil}
				if e != nil {
					item.Error = e.Error()
					result.Passed = false
				}
				result.Cases = append(result.Cases, item)
			}
		}
	}
	if err != nil {
		result.Error = err.Error()
	}
	if e := json.NewEncoder(f).Encode(result); e != nil {
		fmt.Fprintln(os.Stderr, "Cannot write report")
		return 1
	}
	if !result.Passed {
		fmt.Fprintln(os.Stderr, "Native check failed; see JSON report")
		return 1
	}
	fmt.Println("PASS: original Windows helper RSA/CChannel/SRP, matching keys and rekey continuity; no VPN connection created")
	return 0
}
func main() { os.Exit(run()) }
