// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Attestations;

/// <summary>
/// Represents the resolved signing parameters for one AuthProxy-signed assertion.
/// </summary>
/// <param name="Issuer">The issuer written to the assertion's <c>iss</c> claim, naming the AuthProxy deployment that signed it.</param>
/// <param name="Audience">The audience written to the assertion's <c>aud</c> claim, naming the single application entitled to consume it.</param>
/// <param name="KeyId">The identifier of the resolved active signing key, written to the JWS <c>kid</c> header so a verifier can select the matching public key.</param>
/// <param name="PrivateKeyPem">The PEM-encoded RSA private key belonging to <paramref name="KeyId"/>.</param>
/// <param name="Lifetime">The lifetime applied to the assertion, from which its <c>exp</c> claim is derived.</param>
/// <remarks>
/// The contract is the boundary between a configuration section and <see cref="AttestationSigner"/>. Each
/// signed protocol resolves its own active key from its own configuration and hands the result over, so one
/// signing implementation serves every protocol without any of them sharing a configuration shape.
/// </remarks>
public sealed record AttestationSigningContract(
    string Issuer,
    string Audience,
    string KeyId,
    string PrivateKeyPem,
    TimeSpan Lifetime);
