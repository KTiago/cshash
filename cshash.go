package cshash

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

const (
	// Types
	BOOLEAN           = 0x01
	INTEGER           = 0x02
	BIT_STRING        = 0x03
	OCTET_STRING      = 0x04
	NULL              = 0x05
	OBJECT_IDENTIFIER = 0x06
	OBJECT_DESCRIPTOR = 0x07
	EXTERNAL          = 0x08
	REAL              = 0x09
	UTF8_STRING       = 0x0C
	PRINTABLE_STRING  = 0x13
	IA5STRING         = 0x16
	UTC_TIME          = 0x17
	GENERALIZED_TIME  = 0x18
	SEQUENCE          = 0x30
	SET               = 0x31
	VERSION           = 0xA0
	ISSUER_UNIQUE_ID  = 0xA1
	SUBJECT_UNIQUE_ID = 0xA2
	EXTENSION         = 0xA3

	// Object identifiers used in X.509 certificates
	KEY_USAGE               = 0x551D0F
	EXT_KEY_USAGE           = 0x551D25
	BASIC_CONSTRAINTS       = 0x551D13
	AUTHORITY_INFO_ACCESS   = 0x2B06010505070101
	CERTIFICATE_POLICIES    = 0x551D20
	CRL_DISTRIBUTION_POINTS = 0x0551D1F
)

var TYPE = map[int]string{
	BOOLEAN : `"BOOLEAN"`,
	INTEGER : `"INTEGER"`,
	BIT_STRING  : `"BIT_STRING"`,
	OCTET_STRING : `"OCTET_STRING"`,
	NULL : `"NULL"`,
	OBJECT_IDENTIFIER : `"OBJECT_IDENTIFIER"`,
	OBJECT_DESCRIPTOR : `"OBJECT_DESCRIPTOR"`,
	EXTERNAL          : `"EXTERNAL"`,
	REAL              : `"REAL"`,
	UTF8_STRING       : `"UTF8_STRING"`,
	PRINTABLE_STRING  : `"PRINTABLE_STRING"`,
	IA5STRING         : `"IA5STRING"`,
	UTC_TIME          : `"UTC_TIME"`,
	GENERALIZED_TIME  : `"GENERALIZED_TIME"`,
	SEQUENCE          : `"SEQUENCE"`,
	SET               : `"SET"`,
	VERSION           : `"VERSION"`,
	ISSUER_UNIQUE_ID  : `"ISSUER_UNIQUE_ID"`,
	SUBJECT_UNIQUE_ID : `"SUBJECT_UNIQUE_ID"`,
	EXTENSION         : `"EXTENSION"`,
}

type ParseError struct {
	Msg string
}

func (e *ParseError) Error() string {
	return e.Msg
}

func new(text string) error {
	return &ParseError{text}
}

func byteToString(value byte) string{
	result, exists := TYPE[int(value)]
	if exists{
		return result
	}
	return `"UNKNOWN"`
}

func shouldBeIncluded(identifier []byte) bool {
	int_identifier := bytesToInt(identifier)
	switch int_identifier {
	//case KEY_USAGE, EXT_KEY_USAGE, BASIC_CONSTRAINTS, AUTHORITY_INFO_ACCESS, CERTIFICATE_POLICIES, CRL_DISTRIBUTION_POINTS:
	case KEY_USAGE, EXT_KEY_USAGE, BASIC_CONSTRAINTS:
		return true
	}
	return false
}

func isKnownComposite(value byte) bool {
	switch value {
	case SEQUENCE, SET, VERSION, EXTENSION:
		return true
	}
	return false
}

func bytesToInt(bytes []byte) int {
	result := 0
	for i := 0; i < len(bytes); i++ {
		result += int(bytes[i]) * int(math.Pow(256, float64((len(bytes)-i-1))))
	}
	return result
}

func OIDToString(bytes []byte) string{
	result := ""
	if len(bytes) == 0{
		return result
	}
	result += strconv.Itoa(int(bytes[0]) / 40) + "." + strconv.Itoa(int(bytes[0]) % 40)
	value := 0
	for i := 1; i < len(bytes); i++{
		if int(bytes[i]) < 128 && value == 0{
			result += "." + strconv.Itoa(int(bytes[i]))
		} else if int(bytes[i]) < 128 && value != 0{
			value *= 128
			value += int(bytes[i])
			result += "." + strconv.Itoa(value)
			value = 0
		} else{
			value *= 128
			value += int(bytes[i]) - 128
		}
	}
	return result
}

func hexToString(bytes []byte) string{
	return strings.ToUpper(hex.EncodeToString(bytes))
}

func PEMToBase64(cert string) string {
	cert = strings.Replace(cert, "-BEGIN CERTIFICATE-", "", 1)
	cert = strings.Replace(cert, "-END CERTIFICATE-", "", 1)
	cert = strings.Replace(cert, "-", "", -1)
	cert = strings.Replace(cert, " ", "", -1)
	cert = strings.Replace(cert, "\n", "", -1)
	return cert
}

func PEMToDER(cert string) ([]byte, error){
	certBase64 := PEMToBase64(cert)
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	return certDER, err
}

func printJSON(data string) string{
	src := []byte(data)
	dst := &bytes.Buffer{}
	if err := json.Indent(dst, src, "", "  "); err != nil {
		panic(err)
	}
	return dst.String()
}

func ParseStructure(certDER []byte, prettyPrint bool) string{
	parsed := strings.Join(ParseStructureRec(certDER), "")
	if prettyPrint{
		return printJSON(parsed)
	} else{
		return parsed
	}
}

func Fingerprint(certDER []byte) string {
	parsed := ParseStructure(certDER, false)
	//fmt.Println(parsed)
	//fmt.Println(printJSON(parsed))
	data := []byte(parsed)
	csf := md5.Sum(data)
	return hex.EncodeToString(csf[:])
}

/*
Given the bytes of a DER encoded X.509 certificate, returns an array of bytes that is unique
to the ASN1 structure of the certificate and does not depend on the contents of the certificate.
*/
func ParseStructureRec(bytes []byte) (structure []string) {
	if bytes == nil {
		return
	}
	i := 0
	includeObject := false
	structure = append(structure, "{")
	for {
		if i == len(bytes) {
			break
		} else if i != 0{
			structure = append(structure, ",")
		}
		type_ := bytes[i]
		structure = append(structure, byteToString(type_))
		i += 1
		// Reads length of the value and increments cursor accordingly
		length := 0
		if bytes[i] < 128 {
			length = int(bytes[i])
			i += 1
		} else if bytes[i] > 128 {
			lengthLength := int(bytes[i] & 0x7f)
			length = bytesToInt(bytes[i+1 : i+1+lengthLength])
			i += lengthLength + 1
		} else {
			length = 0
			i += 1
		}
		if isKnownComposite(type_) { // For composite objects, recursively parse the inner data
			parsed := ParseStructureRec(bytes[i : i+length])
			structure = append(structure, ":")
			structure = append(structure, parsed...)
		} else if type_ == OBJECT_IDENTIFIER { // Adds content of object identifier
			structure = append(structure, `:"`+OIDToString(bytes[i:i+length])+`"`)
			if shouldBeIncluded(bytes[i : i+length]) { // For some specific objects, we include the content in the hash
				includeObject = true
			}
		} else if (type_ == OCTET_STRING || type_ == BIT_STRING) && includeObject {
			structure = append(structure, `:"`+hexToString(bytes[i:i+length])+`"`)
			includeObject = false
		} else if type_ == BOOLEAN{
			structure = append(structure, `:"`+hexToString(bytes[i:i+length])+`"`)
		} else if type_ == NULL{
			structure = append(structure, `:""`)
		} else {
			structure = append(structure, `:"REMOVED"`)
		}
		i += length
	}
	structure = append(structure, "}")
	return structure
}
