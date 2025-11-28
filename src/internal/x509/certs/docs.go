// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package x509certs provides specialized encoding and decoding operations for [X.509] certificates.
// It supports multiple formats including [PEM], DER, and [PKCS7], and provides
// utilities for handling certificate blocks and bundles. This package is used
// by the chain resolver to parse inputs and format outputs.
//
// [X.509]: https://grokipedia.com/page/X.509
// [PKCS7]: https://grokipedia.com/page/PKCS_7
// [PEM]: https://grokipedia.com/page/PEM#privacy-enhanced-mail
package x509certs
