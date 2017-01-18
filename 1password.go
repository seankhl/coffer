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
//	"strconv"
	"strings"
	"unicode/utf8"
//	"log"
//	"bytes"
)

func main() {
	path := "/mnt/c/Users/sean/Dropbox/1Password.opvault/default/"
	profileRaw, err := ioutil.ReadFile(path + "profile.js") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	profileE := []byte(profileRaw[12:len(profileRaw)-1])
	//fmt.Printf("profile.js: %s\n", profileRaw)
	//fmt.Println()

	// unmarshal profile.js
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
	var p OPWProfile
	json.Unmarshal(profileE, &p)
	fmt.Printf("p: %+v\n", p)
	fmt.Println()

	// obtain master password
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter master password: ")
	masterPass, _ := reader.ReadString('\n')
	masterPass = strings.TrimSuffix(masterPass, "\n")
	fmt.Printf("masterPass is utf-8? %t\n", utf8.ValidString(masterPass))
	fmt.Printf("masterPass: %s\n", masterPass)
	fmt.Println()

	// obtain encryption key and MAC key
	salt, _ := base64.StdEncoding.DecodeString(p.Salt)
	derivedKey := pbkdf2.Key([]byte(masterPass), salt, p.Iterations, 64, sha512.New)
	fmt.Printf("derivedKey: %d\n", derivedKey)
	fmt.Println()

	// decrypt masterKey ciphertext with derivedKey -> 256 byte plaintext content
	// hash masterKey plaintext with SHA-512
	//   1st 32 bytes: master encryption key
	//   2nd 32 bytes: master hmac key

	// base64 -> string for masterKey
	masterCtxt, err := base64.StdEncoding.DecodeString(p.MasterKey)
	if err != nil {
		fmt.Print(err)
		return
	}
	//fmt.Printf("masterCtxt: %d\n", masterCtxt)
	//fmt.Println()

	// parse opdata
	type Opdata struct {
		header string
		length uint64
		ivec []byte
		ctxt []byte
		hmac []byte
	}
	var masterOpdata Opdata
	masterOpdata.header = string(masterCtxt[0:8])

	masterOpdata.length = binary.LittleEndian.Uint64(masterCtxt[8:16])
	padding := uint64(len(masterCtxt)) - (32 + masterOpdata.length + 32)
	indHmac := 32 + padding + masterOpdata.length

	masterOpdata.ivec = masterCtxt[16:32]
	masterOpdata.ctxt = masterCtxt[32:indHmac]
	masterOpdata.hmac = masterCtxt[indHmac:]

	fmt.Printf("> len(derivedKey): %d\n", len(derivedKey))
	fmt.Printf("> len(masterCtxt): %d\n", len(masterCtxt))
	fmt.Printf("> padding: %d\n", padding)
	fmt.Printf("opdata.header: %s\n", masterOpdata.header)
	fmt.Printf("opdata.length: %d\n", masterOpdata.length)
	fmt.Printf("opdata.ivec: %d\n", masterOpdata.ivec)
	fmt.Printf("opdata.ctxt: %d\n", masterOpdata.ctxt)
	fmt.Printf("opdata.hmac: %d\n", masterOpdata.hmac)
	fmt.Println()

	// decrypt masterKey

	h := hmac.New(sha256.New, derivedKey[32:])
	h.Write(masterCtxt[:indHmac])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, masterOpdata.hmac) {
		fmt.Printf("bad hmac: %d\n", mac)
	}

	masterPtxt := make([]byte, 272)
	c, _ := aes.NewCipher(derivedKey[:32])
	ctr := cipher.NewCBCDecrypter(c, masterOpdata.ivec)
	ctr.CryptBlocks(masterPtxt, masterOpdata.ctxt)
	masterPtxt = masterPtxt[padding:]

	masterKey := sha512.Sum512(masterPtxt)
	fmt.Printf("masterKey: %d\n", masterKey)

	// overviewKey

	// band_0

	band_0Raw, err := ioutil.ReadFile(path + "band_0.js") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	band_0E := []byte(band_0Raw[3:len(band_0Raw)-2])
	fmt.Printf("band_0.js: %s\n", band_0Raw)
	fmt.Println()

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
	var band_0Data OPWBand
	json.Unmarshal(band_0E, &band_0Data)

	for k, v := range band_0Data {
		fmt.Printf("%s: %+v\n", k, v)
	}



	fmt.Println("DONE")
}

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
