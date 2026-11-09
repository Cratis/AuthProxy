// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Preserved account-key and authentication evidence, not derived from issuance or refresh time.</summary>
/// <param name="Issuer">The realm-issued account-key issuer.</param>
/// <param name="Subject">The immutable lowercase UUID-v4 subject.</param>
/// <param name="IdentityProvider">The verified upstream authority.</param>
/// <param name="AuthenticationTime">The original canonical integer NumericDate.</param>
/// <param name="AuthenticationContext">The connection-mapped authentication strength.</param>
public sealed record ForwardedIdentityPersonEvidence(string Issuer, string Subject, string IdentityProvider, string AuthenticationTime, string AuthenticationContext)
{
    /// <inheritdoc/>
    public override string ToString() => nameof(ForwardedIdentityPersonEvidence);
}
