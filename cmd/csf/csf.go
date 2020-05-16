package main

import (
	"flag"
	"fmt"
	"github.com/KTiago/csf"
	"io/ioutil"
	"encoding/base64"
)

var (
	input  = flag.String("i", "-", "Input file")
	format = flag.String("inform", "base64", "Input format - (one of base64, PEM or DER)")
)

func main() {
	flag.Usage = func() {
		fmt.Println( "Usage: csf [options] [certificate in base64]\nPrint the Certificate Structure Fingerprint (csf) of the given base64 DER certificate.\n\nWith no Input file, or when Input file is -, read from standard input. (base64 only)")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	certDer := []byte{}
	var err error
	if *input == "-"{
		if len(args) != 1{
			flag.Usage()
		}else{
			cert := args[0]
			certDer, err = base64.StdEncoding.DecodeString(cert)
			if err != nil {
				panic(err)
			}
		}
	} else {
		if *format == "DER"{
			certDer, err = ioutil.ReadFile(*input)
			if err != nil {
				panic(err)
			}
		} else if *format == "PEM" || *format == "base64"{
			cert, err := ioutil.ReadFile(*input)
			if err != nil {
				panic(err)
			}
			parsedCert := csf.ParsePEM(string(cert))
			certDer, err = base64.StdEncoding.DecodeString(parsedCert)
			if err != nil {
				panic(err)
			}
		}
	}
	csfDigest := csf.Fingerprint(certDer)
	fmt.Printf("%s\n",csfDigest)
}
