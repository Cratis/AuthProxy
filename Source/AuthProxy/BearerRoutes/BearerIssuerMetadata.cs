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
/// Each issuer keeps its last good keys. Requested refreshes finish before keys are returned, so a token naming
/// a newly rotated key can be retried in the same request. Retrievals are serialized per issuer and failed
/// retrievals back off, including before the first success. An outage does not discard previously trusted keys.
/// Metadata naming another issuer is never cached or trusted.
/// </remarks>
public sealed class BearerIssuerMetadata(
    IHttpClientFactory httpClientFactory,
    ILogger<BearerIssuerMetadata> logger) : IBearerIssuerMetadata, IDisposable
{
    /// <summary>
    /// The shortest interval between two requested refreshes of one issuer's metadata, and the failure backoff.
    /// </summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(30);

    readonly ConcurrentDictionary<(string Issuer, string Address, bool RequireHttps), BearerIssuerMetadataCache> _caches = new();

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<SecurityKey>?> GetSigningKeys(ResolvedBearerIssuer issuer, CancellationToken cancellationToken)
    {
        var cache = CacheFor(issuer);
        await cache.Gate.WaitAsync(cancellationToken);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var requested = cache.TakeRefreshRequest();
            if (now >= cache.RetryAfter &&
                (cache.Configuration is null || now >= cache.AutomaticRefreshAfter || (requested && now >= cache.RequestedRefreshAfter)))
            {
                if (requested)
                {
                    cache.RequestedRefreshAfter = now + RefreshInterval;
                }

                try
                {
                    var configuration = await OpenIdConnectConfigurationRetriever.GetAsync(issuer.MetadataAddress, cache.Retriever, cancellationToken);
                    if (string.Equals(configuration.Issuer, issuer.Issuer, StringComparison.Ordinal))
                    {
                        cache.Configuration = configuration;
                        cache.AutomaticRefreshAfter = DateTimeOffset.UtcNow + ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
                    }
                    else
                    {
                        logger.IssuerMetadataNamesAnotherIssuer(issuer.Issuer, issuer.MetadataAddress);
                        cache.RetryAfter = DateTimeOffset.UtcNow + RefreshInterval;
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    cache.RetryAfter = DateTimeOffset.UtcNow + RefreshInterval;
                    logger.IssuerMetadataUnavailable(exception, issuer.Issuer, issuer.MetadataAddress);
                }
            }

            return cache.Configuration is { } cached ? [.. cached.SigningKeys] : null;
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    /// <inheritdoc/>
    public void RequestRefresh(ResolvedBearerIssuer issuer) => CacheFor(issuer).RequestRefresh();

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var cache in _caches.Values)
        {
            cache.Dispose();
        }
    }

    BearerIssuerMetadataCache CacheFor(ResolvedBearerIssuer issuer) =>
        _caches.GetOrAdd(
            (issuer.Issuer, issuer.MetadataAddress, issuer.RequireHttps),
            static (key, factory) => new BearerIssuerMetadataCache(new HttpDocumentRetriever(factory.CreateClient(BearerRouteDefaults.MetadataHttpClientName))
            {
                RequireHttps = key.RequireHttps,
            }),
            httpClientFactory);
}
