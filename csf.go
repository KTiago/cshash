package csf

import (
	"crypto/md5"
	"encoding/hex"
	"math"
)

const(
	// Types
	BOOLEAN = 0x01
	INTEGER = 0x02
	BIT_STRING = 0x03
	OCTET_STRING = 0x04
	NULL = 0x05
	OBJECT_IDENTIFIER = 0x06
	OBJECT_DESCRIPTOR = 0x07
	SEQUENCE = 0x30
	SET = 0x31
	VERSION = 0xA0
	ISSUER_UNIQUE_ID = 0xA1
	SUBJECT_UNIQUE_ID = 0xA2
	EXTENSION = 0xA3

	// Object identifiers used in X.509 certificates
	KEY_USAGE = 0x551D0F
	EXT_KEY_USAGE = 0x551D25
	BASIC_CONSTRAINTS = 0x551D13
	AUTHORITY_INFO_ACCESS = 0x2B06010505070101
	CERTIFICATE_POLICIES = 0x551D20
	CRL_DISTRIBUTION_POINTS = 0x0551D1F
)

type ParseError struct {
	Msg string
}

func (e *ParseError) Error() string {
	return e.Msg
}

func New(text string) error {
	return &ParseError{text}
}

func shouldBeIncluded(identifier []byte)bool{
	int_identifier := bytesToInt(identifier)
	return int_identifier == KEY_USAGE || int_identifier == EXT_KEY_USAGE ||
		int_identifier == BASIC_CONSTRAINTS || int_identifier == AUTHORITY_INFO_ACCESS ||
		int_identifier == CERTIFICATE_POLICIES || int_identifier == CRL_DISTRIBUTION_POINTS
}

func isKnownComposite(value byte) bool {
	return value == SEQUENCE || value == SET || value == VERSION || value == EXTENSION
}

func bytesToInt(bytes []byte) int{
	result := 0
	for i := 0; i < len(bytes); i++{
		result += int(bytes[i]) * int(math.Pow(256, float64((len(bytes) - i - 1))))
	}
	return result
}

func Fingerprint(bytes []byte) string{
	hash := md5.Sum(Parse(bytes))
	return hex.EncodeToString(hash[:])
}

/*
Given the bytes of a DER encoded X.509 certificate, returns an array of bytes that is unique
to the ASN1 structure of the certificate and does not depend on the contents of the certificate.
 */
func Parse(bytes []byte) (structure []byte){
	if bytes == nil{
		return
	}
	i := 0
	includeObject := false
	for {
		if i == len(bytes){
			return
		}
		type_ := bytes[i]
		structure = append(structure, type_)
		i += 1
		// Reads length of the value and increments cursor accordingly
		length := 0
		if (bytes[i] < 128){
			length = int(bytes[i])
			i += 1
		} else if (bytes[i] > 128) {
			lengthLength := int(bytes[i] & 0x7f)
			length = bytesToInt(bytes[i+1:i+1+lengthLength])
			i += lengthLength + 1
		} else {
			length = 0
			i += 1
		}
		if isKnownComposite(type_){ // For composite objects, recursively parse the inner data
			parsed := Parse(bytes[i:i+length])
			structure = append(structure, parsed...)
		} else if type_ == OBJECT_IDENTIFIER { // Adds content of object identifier
			structure = append(structure, bytes[i:i+length]...)
			if shouldBeIncluded(bytes[i:i+length]){ // For some specific objects, we include the content in the hash
				includeObject = true
			}
		} else if (type_ == OCTET_STRING || type_ == BIT_STRING) && includeObject{
			structure = append(structure, bytes[i:i+length]...)
			includeObject = false
		}
		i += length
	}
}
