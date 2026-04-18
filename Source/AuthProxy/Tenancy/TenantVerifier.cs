// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Tenancy;

/// <summary>
/// Verifies tenant existence by issuing an HTTP GET to a configurable URL template.
/// </summary>
/// <remarks>
/// When <see cref="Cratis.AuthProxy.Configuration.TenantVerification.UrlTemplate"/> is empty or not configured the
/// verifier returns <see langword="true"/> for all tenants (verification is disabled).
/// </remarks>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="httpClientFactory">The factory used to create the HTTP client for verification calls.</param>
/// <param name="logger">The logger.</param>
public class TenantVerifier(
    IOptionsMonitor<C.AuthProxy> config,
    IHttpClientFactory httpClientFactory,
    ILogger<TenantVerifier> logger) : ITenantVerifier
{
    /// <inheritdoc/>
    public async Task<bool> VerifyAsync(string tenantId, string? urlTemplateOverride = null)
    {
        var urlTemplate = string.IsNullOrWhiteSpace(urlTemplateOverride)
            ? config.CurrentValue.TenantVerification?.UrlTemplate
            : urlTemplateOverride;

        if (string.IsNullOrWhiteSpace(urlTemplate))
        {
            return true;
        }

        var url = urlTemplate.Replace("{tenantId}", tenantId, StringComparison.Ordinal);
        using var client = httpClientFactory.CreateClient();

        try
        {
            var response = await client.GetAsync(url);

            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                logger.TenantNotFound(tenantId);
                return false;
            }

            logger.TenantVerificationFailed(tenantId, (int)response.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            logger.TenantVerificationError(ex, tenantId, url);
            return false;
        }
    }
}
