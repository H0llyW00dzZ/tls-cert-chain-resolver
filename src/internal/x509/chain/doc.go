// Copyright (c) 2025 H0llyW00dzZ All rights reserved.
//
// By accessing or using this software, you agree to be bound by the terms
// of the License Agreement, which you can find at LICENSE files.

// Package x509chain implements [X.509] certificate chain resolution and validation logic.
// It provides capabilities to:
//   - Resolve incomplete chains by fetching intermediate certificates via AIA URLs.
//   - Validate chains against system roots or custom root pools.
//   - Check revocation status using [OCSP] and [CRL] with caching and fallback mechanisms.
//   - Fetch remote certificate chains from TLS endpoints.
//
// The package handles context-aware cancellation and HTTP client configuration
// for reliable network operations.
//
// [X.509]: https://grokipedia.com/page/X.509
// [OCSP]: https://grokipedia.com/page/Online_Certificate_Status_Protocol
// [CRL]: https://grokipedia.com/page/Certificate_revocation_list
package x509chain
