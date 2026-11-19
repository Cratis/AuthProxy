// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>An external issuer whose tokens may only be exchanged, never accepted raw.</summary>
public sealed class BearerTokenExchangeIssuer
{
    /// <summary>Gets or sets the exact external issuer.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>Gets or sets jwt or access_token, mapped to the RFC token-type URN.</summary>
    public string SubjectTokenType { get; set; } = "jwt";
}
