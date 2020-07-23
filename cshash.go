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

type Byte byte

func safeGet(array []byte, index int) (byte, error){
	if index >= 0 && index < len(array){
		return array[index], nil
	}else{
		return 0, &ParseError{"index out of bounds"}
	}
}

func safeSlice(array []byte, low int, high int) ([]byte, error){
	if 0 <= low && low <= high && high <= len(array){
		return array[low:high], nil
	}else{
		return nil, &ParseError{"index out of bounds"}
	}
}

func byteToString(value byte) string{
	result, exists := TYPE[int(value)]
	if exists{
		return result
	}
	return `"UNKNOWN"`
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

func ParseStructure(certDER []byte, prettyPrint bool) (string, error){
	structure, err := ParseStructureRec(certDER)
	if err != nil{
		return "", err
	}
	parsed := strings.Join(structure, "")
	if prettyPrint{
		return strings.ReplaceAll(printJSON(parsed), "\"", ""), nil
	} else{
		return strings.ReplaceAll(parsed, "\"", ""), nil
	}
}

func Fingerprint(certDER []byte) string {
	parsed, err := ParseStructure(certDER, false)
	if err != nil{
		return "parsing error"
	}
	parsed = strings.ReplaceAll(parsed, "\"", "")
	data := []byte(parsed)
	csf := md5.Sum(data)
	return hex.EncodeToString(csf[:])
}

/*
Given the bytes of a DER encoded X.509 certificate, returns an array of bytes that is unique
to the ASN1 structure of the certificate and does not depend on the contents of the certificate.
*/
func ParseStructureRec(bytes []byte) (structure []string, err error) {
	if bytes == nil {
		return
	}
	i := 0
	structure = append(structure, "{")
	for {
		if i == len(bytes) {
			break
		} else if i != 0{
			structure = append(structure, ",")
		}

		type_, err := safeGet(bytes, i)
		if err != nil{
			return nil, err
		}

		structure = append(structure, byteToString(type_))
		i += 1

		// Reads length of the value and increments cursor accordingly
		length := 0

		firstByte, err := safeGet(bytes, i)
		if err != nil{
			return nil, err
		}

		if firstByte < 128 {
			length = int(firstByte)
			i += 1
		} else if firstByte > 128 {
			lengthLength := int(firstByte & 0x7f)

			slice, err := safeSlice(bytes, i+1, i+1+lengthLength)
			if err != nil{
				return nil, err
			}

			length = bytesToInt(slice)
			i += lengthLength + 1
		} else {
			length = 0
			i += 1
		}

		value, err := safeSlice(bytes, i, i+length)
		if err != nil{
			return nil, err
		}

		if isKnownComposite(type_) { // For composite objects, recursively parse the inner data
			parsed, err := ParseStructureRec(value)
			if err != nil{
				return nil, err
			}
			structure = append(structure, ":")
			structure = append(structure, parsed...)
		} else if type_ == OBJECT_IDENTIFIER { // Adds content of object identifier
			structure = append(structure, `:"`+OIDToString(value)+`"`)
		} else {
			structure = append(structure, `:"∅"`)
		}
		i += length
	}
	structure = append(structure, "}")
	return structure, nil
}
