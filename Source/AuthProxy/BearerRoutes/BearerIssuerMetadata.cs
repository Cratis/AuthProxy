// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes;

/// <summary>
/// Reads and caches the signing keys bearer-token issuers publish.
/// </summary>
/// <param name="httpClientFactory">The factory for the client the metadata and JWKS are read with.</param>
/// <param name="logger">The logger.</param>
/// <remarks>
/// One configuration manager per metadata address holds the last good metadata and keys, refreshes them
/// periodically, and refreshes them on request when a token names an unknown key — which is how key rotation at the
/// issuer is picked up. A refresh that fails keeps the last good keys, so an issuer outage after the first retrieval
/// does not refuse tokens that were signed with a key already known.
/// <para>
/// The metadata must name exactly the configured issuer. A document that names another one is refused rather than
/// trusted: the keys it points at belong to whoever that other issuer is.
/// </para>
/// </remarks>
public sealed class BearerIssuerMetadata(
    IHttpClientFactory httpClientFactory,
    ILogger<BearerIssuerMetadata> logger) : IBearerIssuerMetadata
{
    /// <summary>
    /// The shortest interval between two requested refreshes of one issuer's metadata.
    /// </summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    readonly ConcurrentDictionary<(string Address, bool RequireHttps), ConfigurationManager<OpenIdConnectConfiguration>> _managers = new();

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<SecurityKey>?> GetSigningKeys(ResolvedBearerIssuer issuer, CancellationToken cancellationToken)
    {
        try
        {
            var configuration = await ManagerFor(issuer).GetConfigurationAsync(cancellationToken);
            if (!string.Equals(configuration.Issuer, issuer.Issuer, StringComparison.Ordinal))
            {
                logger.IssuerMetadataNamesAnotherIssuer(issuer.Issuer, issuer.MetadataAddress);
                return null;
            }

            return [.. configuration.SigningKeys];
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.IssuerMetadataUnavailable(exception, issuer.Issuer, issuer.MetadataAddress);
            return null;
        }
    }

    /// <inheritdoc/>
    public void RequestRefresh(ResolvedBearerIssuer issuer) => ManagerFor(issuer).RequestRefresh();

    ConfigurationManager<OpenIdConnectConfiguration> ManagerFor(ResolvedBearerIssuer issuer) =>
        _managers.GetOrAdd(
            (issuer.MetadataAddress, issuer.RequireHttps),
            static (key, factory) => new ConfigurationManager<OpenIdConnectConfiguration>(
                key.Address,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(factory.CreateClient(BearerRouteDefaults.MetadataHttpClientName))
                {
                    RequireHttps = key.RequireHttps,
                })
            {
                RefreshInterval = RefreshInterval,
            },
            httpClientFactory);
}
