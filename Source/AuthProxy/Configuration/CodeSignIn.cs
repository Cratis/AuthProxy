// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>
/// Settings of a provider whose <see cref="OidcProvider.Type"/> is <see cref="OidcProviderType.Code"/>: AuthProxy issues
/// and verifies a one-time code, and the application decides who is eligible and delivers the e-mail.
/// </summary>
public class CodeSignIn
{
    /// <summary>
    /// Gets or sets the application endpoint AuthProxy posts a signed code request to.
    /// </summary>
    public string RequestUrl { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the signing settings of the request to the application, so the application can tell it is AuthProxy
    /// asking it to send a code. Independent of <c language="text">SignIn:Attestation</c>.
    /// </summary>
    public SignInAttestation? Attestation { get; set; }

    /// <summary>
    /// Gets or sets the issuer a canonical identity is attributed to: an absolute HTTPS address that names this sign-in and
    /// never changes. It is part of the identity key, so every AuthProxy that should recognise the same people uses the same value.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the number of digits in a code.
    /// </summary>
    public int CodeLength { get; set; } = 6;

    /// <summary>
    /// Gets or sets how long a code can be used.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets the number of wrong codes a challenge tolerates before it is destroyed.
    /// </summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>
    /// Gets or sets the limits on how often a code can be requested.
    /// </summary>
    public CodeThrottle Throttle { get; set; } = new();
}
