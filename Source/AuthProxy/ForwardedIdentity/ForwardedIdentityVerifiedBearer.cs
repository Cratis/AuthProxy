// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity;

/// <summary>Successful verification evidence for one exact token, supplied by its own credential verifier.</summary>
/// <param name="Token">The exact verified token, never logged.</param>
/// <param name="Verifier">Either <c language="text">pat-verifier</c> or <c language="text">oauth-verifier</c>.</param>
/// <param name="Issuer">The verified bearer's account-key issuer.</param>
/// <param name="Subject">The verified bearer's account-key subject.</param>
public sealed record ForwardedIdentityVerifiedBearer(string Token, string Verifier, string Issuer, string Subject)
{
    /// <inheritdoc/>
    public override string ToString() => nameof(ForwardedIdentityVerifiedBearer);
}
