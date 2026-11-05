// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire;

/// <summary>The exception that is thrown when a published pairing has no provisioned signing key.</summary>
/// <param name="backend">The backend resource name.</param>
public class ForwardedIdentitySigningKeyNotProvisioned(string backend)
    : Exception($"Provision a signing key for '{backend}': pass signingKey: from a secret parameter. Pairing never generates keys into a published manifest.");
