# CSHash
## Certificate Structure Hash library and command line tool in Go.

CSHash is a unique value computed from the structure of a given X.509 (TLS) certificates. This can be used to identify different certificates generated using the same libraries or scripts, since such certificates tend to have similar structures but different contents.

A CSHash is computed in two steps. First, the ASN.1 structure of the certificate is extracted in the form of a JSON-like string. Then, the md5 hash is computed over the string to produce easily shareable, fixed-length values.

## Building
The following command requires the `$GOPATH` environment variable to be set. It will download the package to your workspace.
```
$ go get github.com/KTiago/cshash
```
You can build the project with the following commands.
```
$ cd $GOPATH/src/github.com/KTiago/cshash
$ make build
```
This will create the executable `cshash` in the folder `$GOPATH/src/github.com/KTiago/cshash`. You are ready to compute the CSHash of a certificate.
```
$ ./cshash -i example.pem
759eedf155aa5a24e49bd1f00eea5bfb
```
## Example
Below is the extracted structure of an example self-signed certificate for "C=XX, L=Default City, O=Default Company Ltd" in an JSON-like format. The CSHash is the md5 hash over the below string where spaces and line returns have been removed.
```
$ ./cshash -i example.pem --struct --pretty
{
  SEQUENCE: {
    SEQUENCE: {
      VERSION: {
        INTEGER: ∅
      },
      INTEGER: ∅,
      SEQUENCE: {
        OBJECT_IDENTIFIER: 1.2.840.113549.1.1.11,
        NULL: ∅
      },
      SEQUENCE: {
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.6,
            PRINTABLE_STRING: ∅
          }
        },
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.7,
            UTF8_STRING: ∅
          }
        },
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.10,
            UTF8_STRING: ∅
          }
        }
      },
      SEQUENCE: {
        UTC_TIME: ∅,
        UTC_TIME: ∅
      },
      SEQUENCE: {
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.6,
            PRINTABLE_STRING: ∅
          }
        },
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.7,
            UTF8_STRING: ∅
          }
        },
        SET: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.4.10,
            UTF8_STRING: ∅
          }
        }
      },
      SEQUENCE: {
        SEQUENCE: {
          OBJECT_IDENTIFIER: 1.2.840.113549.1.1.1,
          NULL: ∅
        },
        BIT_STRING: ∅
      },
      EXTENSION: {
        SEQUENCE: {
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.29.14,
            OCTET_STRING: ∅
          },
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.29.35,
            OCTET_STRING: ∅
          },
          SEQUENCE: {
            OBJECT_IDENTIFIER: 2.5.29.19,
            BOOLEAN: ∅,
            OCTET_STRING: ∅
          }
        }
      }
    },
    SEQUENCE: {
      OBJECT_IDENTIFIER: 1.2.840.113549.1.1.11,
      NULL: ∅
    },
    BIT_STRING: ∅
  }
}
```
