package main

import (
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha512"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"bufio"
	"fmt"
	"os"
//	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode/utf8"
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
	profileRaw, err := ioutil.ReadFile(path + "profile.js")
	if err != nil {
		fmt.Print(err)
	}
	profileE := []byte(profileRaw[12:len(profileRaw)-1])
	//fmt.Printf("profile.js: %s\n", profileRaw)
	//fmt.Println()

	// unmarshal profile.js
	var p OPWProfile
	json.Unmarshal(profileE, &p)
	fmt.Printf("p: %+v\n", p)
	fmt.Println()
	return p
}

func getMasterPass() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter master password: ")
	masterPass, _ := reader.ReadString('\n')
	masterPass = strings.TrimSuffix(masterPass, "\n")
	fmt.Printf("masterPass is utf-8? %t\n", utf8.ValidString(masterPass))
	fmt.Printf("masterPass: %s\n", masterPass)
	fmt.Println()
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
	bandRaw, err := ioutil.ReadFile(path + bandName + ".js")
	if err != nil {
		fmt.Print(err)
	}
	bandE := []byte(bandRaw[3:len(bandRaw)-2])
	fmt.Printf(bandName + ": %s\n", bandRaw)
	fmt.Println()

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

func main() {
	path := "/mnt/c/Users/sean/Dropbox/1Password.opvault/default/"

	// get profile
	var p OPWProfile = parseProfile(path)

	// get master password
	var masterPass string = getMasterPass()

	// obtain encryption key and MAC key
	salt, _ := base64.StdEncoding.DecodeString(p.Salt)
	derivedKey := pbkdf2.Key([]byte(masterPass), salt, p.Iterations, 64, sha512.New)
	fmt.Printf("derivedKey: %d\n", derivedKey)
	fmt.Println()

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
	fmt.Printf("masterKey: %d\n", masterKey)

	// decrypt overviewKey
	overviewPtxt := decrypt(
		derivedKey, overviewRaw,
		overviewOpdata.ivec, overviewOpdata.ctxt, overviewOpdata.hmac)
	overviewPtxt = overviewPtxt[overviewOpdata.padding:]
	overviewKey := sha512.Sum512(overviewPtxt)
	fmt.Printf("overviewKey: %d\n", overviewKey)

	// band parsing
	bandData := parseBand(path, 0)
	for _, v := range bandData {
		//fmt.Printf("%s: %+v\n", k, v)

		// K
		bandRaw, _ := base64.StdEncoding.DecodeString(v.K)
		fmt.Printf("bandRaw: %d\n", bandRaw)
		bandPtxt := decrypt(
			masterKey[:], bandRaw,
			bandRaw[:16], bandRaw[16:len(bandRaw)-32], bandRaw[len(bandRaw)-32:])
		bandKey := bandPtxt[:]
		fmt.Printf("bandPtxt: %d (%d bytes)\n", bandPtxt, len(bandPtxt))
		fmt.Println("")
		
		// D
		itemRaw, _ := base64.StdEncoding.DecodeString(v.D)
		itemOpdata := parseOpdata(itemRaw)
		itemPtxt := decrypt(
			bandKey, itemRaw,
			itemOpdata.ivec, itemOpdata.ctxt, itemOpdata.hmac)
		itemPtxt = itemPtxt[itemOpdata.padding:]
		fmt.Printf("itemPtxt: %s\n", string(itemPtxt))
		fmt.Println("")
	}

	fmt.Println("DONE")
}

	/*
	fmt.Printf("masterCtxt: %d\n", masterCtxt)
	fmt.Println()
	fmt.Printf("> len(derivedKey): %d\n", len(derivedKey))
	fmt.Printf("> len(masterCtxt): %d\n", len(masterCtxt))
	fmt.Printf("> padding: %d\n", padding)
	fmt.Printf("opdata.header: %s\n", masterOpdata.header)
	fmt.Printf("opdata.length: %d\n", masterOpdata.length)
	fmt.Printf("opdata.ivec: %d\n", masterOpdata.ivec)
	fmt.Printf("opdata.ctxt: %d\n", masterOpdata.ctxt)
	fmt.Printf("opdata.hmac: %d\n", masterOpdata.hmac)
	fmt.Println()
	
	fmt.Printf("> len(derivedKey): %d\n", len(derivedKey))
	fmt.Printf("> len(overviewCtxt): %d\n", len(overviewCtxt))
	fmt.Printf("> padding: %d\n", padding)
	fmt.Printf("opdata.header: %s\n", overviewOpdata.header)
	fmt.Printf("opdata.length: %d\n", overviewOpdata.length)
	fmt.Printf("opdata.ivec: %d\n", overviewOpdata.ivec)
	fmt.Printf("opdata.ctxt: %d\n", overviewOpdata.ctxt)
	fmt.Printf("opdata.hmac: %d\n", overviewOpdata.hmac)
	fmt.Println()
	*/

	/*
	band_0DataMap := band_0Data.(map[string]interface{})
	for k, v := range band_0DataMap {
		switch itemObj := v.(type) {
		case interface{}:
			var item OPWItem
			for itemKey, itemVal := range itemObj.(map[string]interface{}) {
				switch itemKey {
				case "category":
					switch itemVal := itemVal.(type) {
					case string:
						item.Category = itemVal
					}
				case "d":
					switch itemVal := itemVal.(type) {
					case string:
						item.D = itemVal
					}
				case "hmac":
					switch itemVal := itemVal.(type) {
					case string:
						item.Hmac = itemVal
					}
				case "k":
					switch itemVal := itemVal.(type) {
					case string:
						item.K = itemVal
					}
				case "o":
					switch itemVal := itemVal.(type) {
					case string:
						item.O = itemVal
					}
				case "uuid":
					switch itemVal := itemVal.(type) {
					case string:
						item.Uuid = itemVal
					}
				}
			}
			fmt.Printf("%s: %+v\n", k, item)
			fmt.Println()
		}
	}*/
	/*dec := json.NewDecoder(bytes.NewReader(profileE[12:len(profileE)-1]))
	var p map[string]interface{}
	for {
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			fmt.Print(err)
		}
		fmt.Printf("%+v\n", p)
	}
	for k, v := range p {
		fmt.Printf("key[%s] value[%s]\n", k, v)
	}
	
	band_0Decoder := json.NewDecoder(bytes.NewReader(band_0E))
	for {
		if err := band_0Decoder.Decode(&band_0Data); err == io.EOF {
			break
		} else if err != nil {
			fmt.Print(err)
		}
		fmt.Printf("%+v\n", band_0Data)
	}
	*/
