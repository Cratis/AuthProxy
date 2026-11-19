// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Configuration;

/// <summary>Opt-in Identity token exchange for external issuers on a bearer route.</summary>
public sealed class BearerTokenExchange
{
    /// <summary>Gets or sets the trusted HTTPS token endpoint.</summary>
    public string Endpoint { get; set; } = string.Empty;

    /// <summary>Gets or sets the confidential client identifier.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Gets or sets the confidential client secret. Supply through a secret store.</summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>Gets or sets the RFC 8707 resource indicator sent to Identity.</summary>
    public string Resource { get; set; } = string.Empty;

    /// <summary>Gets or sets the separate catalog audience expected in Identity's token.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>Gets or sets the scopes to request, never taken from the caller.</summary>
    public IList<string> Scopes { get; set; } = [];

    /// <summary>Gets or sets the exact local issuer that must issue the result.</summary>
    public string ResultIssuer { get; set; } = string.Empty;

    /// <summary>Gets or sets the per-call deadline.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Gets or sets the maximum number of cached results.</summary>
    public int MaximumCachedTokens { get; set; } = 10000;

    /// <summary>Gets or sets the external issuers explicitly enabled for exchange.</summary>
    public IList<BearerTokenExchangeIssuer> Issuers { get; set; } = [];
}
