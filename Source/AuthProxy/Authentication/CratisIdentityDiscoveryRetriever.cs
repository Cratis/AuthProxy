// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Retrieves the OpenID Connect discovery document of a Cratis Identity provider and refuses it unless its issuer is the
/// configured authority, as OpenID Connect Discovery requires.
/// </summary>
/// <remarks>
/// ID tokens are validated against the issuer the discovery document names, so a document naming another issuer would
/// let that issuer sign people in. The comparison is exact apart from a trailing slash.
/// </remarks>
/// <param name="authority">The configured authority.</param>
public sealed class CratisIdentityDiscoveryRetriever(string authority) : IConfigurationRetriever<OpenIdConnectConfiguration>
{
    /// <inheritdoc/>
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
    {
        var configuration = await OpenIdConnectConfigurationRetriever.GetAsync(address, retriever, cancel);
        if (!IsAuthority(configuration.Issuer))
        {
            throw new CratisIdentityIssuerMismatch(authority);
        }

        return configuration;
    }

    bool IsAuthority(string? issuer) =>
        !string.IsNullOrWhiteSpace(issuer)
        && string.Equals(issuer.TrimEnd('/'), authority.TrimEnd('/'), StringComparison.Ordinal);
}
