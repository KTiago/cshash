# CSHash
## Certificate Structure Hash library and command line tool in Go.

CSHash is a unique value computed from the structure of a given X.509 (TLS) certificates. This can be used to identify different certificates generated using the same libraries or scripts, since such certificates ten to have similar structures but different content.

A CSHash is computed in two steps. First, the ASN.1 structure of the certificate is extracted in the form of a JSON-like string. Then, the md5 hash is computed over the string to produce easily shareable, fixed-length values.

## Example
Below is the extracted structure of a self-signed certificate for "C=AU, O=Internet Widgits Pty Ltd, CN=example.com" in an JSON-like format. The CSHash is the md5 hash over the below string where spaces and line returns have been removed.
```
{
  "SEQUENCE": {
    "SEQUENCE": {
      "VERSION": {
        "INTEGER": "REMOVED"
      },
      "INTEGER": "REMOVED",
      "SEQUENCE": {
        "OBJECT_IDENTIFIER": "1.2.840.113549.1.1.11",
        "NULL": ""
      },
      "SEQUENCE": {
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.6",
            "PRINTABLE_STRING": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.8",
            "UNKNOWN": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.10",
            "UNKNOWN": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.3",
            "UNKNOWN": "REMOVED"
          }
        }
      },
      "SEQUENCE": {
        "UTC_TIME": "REMOVED",
        "UTC_TIME": "REMOVED"
      },
      "SEQUENCE": {
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.6",
            "PRINTABLE_STRING": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.8",
            "UNKNOWN": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.10",
            "UNKNOWN": "REMOVED"
          }
        },
        "SET": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.4.3",
            "UNKNOWN": "REMOVED"
          }
        }
      },
      "SEQUENCE": {
        "SEQUENCE": {
          "OBJECT_IDENTIFIER": "1.2.840.113549.1.1.1",
          "NULL": ""
        },
        "BIT_STRING": "REMOVED"
      },
      "EXTENSION": {
        "SEQUENCE": {
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.29.14",
            "OCTET_STRING": "REMOVED"
          },
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.29.35",
            "OCTET_STRING": "REMOVED"
          },
          "SEQUENCE": {
            "OBJECT_IDENTIFIER": "2.5.29.19",
            "BOOLEAN": "FF",
            "OCTET_STRING": "30030101FF"
          }
        }
      }
    },
    "SEQUENCE": {
      "OBJECT_IDENTIFIER": "1.2.840.113549.1.1.11",
      "NULL": ""
    },
    "BIT_STRING": "REMOVED"
  }
}
```
