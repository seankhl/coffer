package main

import (
	"crypto/sha512"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode/utf8"
	"syscall"
	
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
//	"log"
//	"bytes"
)

type OPWProfile struct {
	LastUpdatedBy string	`json:"lastUpdatedBy"`
	ProfileName string	`json:"profileName"`
	PasswordHint string	`json:"passwordHint"`
	Uuid string		`json:"uuid"`
	Salt string		`json:"salt"`
	Iterations int		`json:"iterations"`
	CreatedAt int		`json:"createdAt"`
	UpdatedAt int		`json:"updatedAt"`
	MasterKey string	`json:"masterKey"`
	OverviewKey string	`json:"overviewKey"`
}

func parseProfile(path string) OPWProfile {
	profileRaw, err := ioutil.ReadFile(path + "/default/profile.js")
	if err != nil {
		fmt.Print(err)
	}
	profileE := []byte(profileRaw[12:len(profileRaw)-1])
	fmt.Fprintf(g_ll, "profile.js: %s\n", profileRaw)
	fmt.Fprintf(g_ll, "\n")

	// unmarshal profile.js
	var p OPWProfile
	json.Unmarshal(profileE, &p)
	fmt.Fprintf(g_ll, "p: %+v\n", p)
	fmt.Fprintf(g_ll, "\n")
	return p
}

func getMasterPass() string {
	fmt.Print("Enter master password: ")
	masterPassBytes, _ := terminal.ReadPassword(int(syscall.Stdin))
	masterPass := strings.TrimSuffix(string(masterPassBytes), "\n")
	fmt.Fprintf(g_ll, "masterPass is utf-8? %t\n", utf8.ValidString(masterPass))
	fmt.Fprintf(g_ll, "masterPass: %s\n", masterPass)
	fmt.Fprintf(g_ll, "\n")
	return masterPass
}

type Opdata struct {
	header string
	length uint64
	padding uint64
	ivec []byte
	ctxt []byte
	hmac []byte
}

func parseOpdata(ctxt []byte) Opdata {
	var opdata Opdata
	opdata.header = string(ctxt[0:8])

	opdata.length = binary.LittleEndian.Uint64(ctxt[8:16])
	opdata.padding = uint64(len(ctxt)) - (32 + opdata.length + 32)
	indHmac := 32 + opdata.padding + opdata.length

	opdata.ivec = ctxt[16:32]
	opdata.ctxt = ctxt[32:indHmac]
	opdata.hmac = ctxt[indHmac:]
	return opdata
}

type OPWItem struct {
	Category string	`json:"category"`
	Created int	`json:"created"`
	D string	`json:"d"`
	Folder string	`json:"folder"`
	Hmac string	`json:"hmac"`
	K string	`json:"k"`
	O string	`json:"o"`
	Tx int		`json:"tx"`
	Updated int	`json:"updated"`
	Uuid string	`json:"uuid"`
}

type OPWBand map[string]OPWItem

func parseBand(path string, band int) OPWBand {
	bandName := "band_" + strconv.Itoa(band)
	bandRaw, err := ioutil.ReadFile(path + "/default/" + bandName + ".js")
	if err != nil {
		fmt.Print(err)
	}
	bandE := []byte(bandRaw[3:len(bandRaw)-2])
	fmt.Fprintf(g_ll, bandName + ": %s\n", bandRaw)
	fmt.Fprintf(g_ll, "\n")

	var bandData OPWBand
	json.Unmarshal(bandE, &bandData)
	return bandData
}

func decrypt(key []byte, raw []byte, ivec []byte, ctxt []byte, vmac []byte) []byte {
	// authenticate
	h := hmac.New(sha256.New, key[32:])
	h.Write(raw[:len(raw)-len(vmac)])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, vmac) {
		fmt.Printf("bad hmac: %d\n", mac)
	}
	// decrypt
	ptxt := make([]byte, len(ctxt))
	c, _ := aes.NewCipher(key[:32])
	ctr := cipher.NewCBCDecrypter(c, ivec)
	ctr.CryptBlocks(ptxt, ctxt)
	return ptxt
}

// global variable that determines where print debugging goes
var g_ll io.Writer

func main() {
	var logMode = "discard"
	switch logMode {
		case "file":
			var err error
			g_ll, err = os.Create("./coffer.log")
			if nil != err {
				panic(err.Error())
			}
		case "screen":
			g_ll = os.Stdout
		default:
			g_ll = ioutil.Discard
	}

	path := "/mnt/c/Users/sean/Documents/1Password/all.opvault"

	// get profile
	var p OPWProfile = parseProfile(path)

	// get master password
	var masterPass string = getMasterPass()

	// obtain encryption key and MAC key
	salt, _ := base64.StdEncoding.DecodeString(p.Salt)
	derivedKey := pbkdf2.Key([]byte(masterPass), salt, p.Iterations, 64, sha512.New)
	fmt.Fprintf(g_ll, "derivedKey: %d\n", derivedKey)
	fmt.Fprintf(g_ll, "")

	// parse masterKey
	masterRaw, _ := base64.StdEncoding.DecodeString(p.MasterKey)
	masterOpdata := parseOpdata(masterRaw)
	
	// parse overviewKey
	overviewRaw, _ := base64.StdEncoding.DecodeString(p.OverviewKey)
	overviewOpdata := parseOpdata(overviewRaw)
	
	// decrypt masterKey
	masterPtxt := decrypt(
		derivedKey, masterRaw,
		masterOpdata.ivec, masterOpdata.ctxt, masterOpdata.hmac)
	masterPtxt = masterPtxt[masterOpdata.padding:]
	masterKey := sha512.Sum512(masterPtxt)
	fmt.Fprintf(g_ll, "masterKey: %d\n", masterKey)

	// decrypt overviewKey
	overviewPtxt := decrypt(
		derivedKey, overviewRaw,
		overviewOpdata.ivec, overviewOpdata.ctxt, overviewOpdata.hmac)
	overviewPtxt = overviewPtxt[overviewOpdata.padding:]
	overviewKey := sha512.Sum512(overviewPtxt)
	fmt.Fprintf(g_ll, "overviewKey: %d\n", overviewKey)

	// band parsing
	bandData := parseBand(path, 0)
	for k, v := range bandData {
		fmt.Fprintf(g_ll, "%s: %+v\n", k, v)

		// K
		bandRaw, _ := base64.StdEncoding.DecodeString(v.K)
		fmt.Fprintf(g_ll, "bandRaw: %d\n", bandRaw)
		bandPtxt := decrypt(
			masterKey[:], bandRaw,
			bandRaw[:16], bandRaw[16:len(bandRaw)-32], bandRaw[len(bandRaw)-32:])
		bandKey := bandPtxt[:]
		fmt.Fprintf(g_ll, "bandPtxt: %d (%d bytes)\n", bandPtxt, len(bandPtxt))
		fmt.Fprintf(g_ll, "\n")
		
		// D
		dRaw, _ := base64.StdEncoding.DecodeString(v.D)
		dOpdata := parseOpdata(dRaw)
		dPtxt := decrypt(
			bandKey, dRaw,
			dOpdata.ivec, dOpdata.ctxt, dOpdata.hmac)
		dPtxt = dPtxt[dOpdata.padding:]
		fmt.Fprintf(g_ll, "dPtxt: %s\n", string(dPtxt))
		var dJson map[string][]map[string]string
		json.Unmarshal(dPtxt, &dJson)
		
		// O
		oRaw, _ := base64.StdEncoding.DecodeString(v.O)
		oOpdata := parseOpdata(oRaw)
		oPtxt := decrypt(
			overviewKey[:], oRaw,
			oOpdata.ivec, oOpdata.ctxt, oOpdata.hmac)
		oPtxt = oPtxt[oOpdata.padding:]
		fmt.Fprintf(g_ll, "oPtxt: %s\n", string(oPtxt))
		var oJson map[string]string
		json.Unmarshal(oPtxt, &oJson)

		fmt.Printf(oJson["title"] + " | ")
		fmt.Printf(dJson["fields"][0]["name"] + ": " + dJson["fields"][0]["value"] + " | ")
		fmt.Printf(dJson["fields"][1]["name"] + ": " + dJson["fields"][1]["value"] + "\n")
		
		fmt.Fprintf(g_ll, "\n")
	}
	
	fmt.Fprintf(g_ll, "DONE")
}
