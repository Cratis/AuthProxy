// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.Ingress.Configuration;
using Microsoft.Extensions.Options;

namespace Cratis.Ingress.Tenancy;

/// <summary>
/// Verifies tenant existence by issuing an HTTP GET to a configurable URL template.
/// </summary>
/// <remarks>
/// When <see cref="TenantVerificationConfig.UrlTemplate"/> is empty or not configured the
/// verifier returns <see langword="true"/> for all tenants (verification is disabled).
/// </remarks>
/// <param name="config">The ingress configuration monitor.</param>
/// <param name="httpClientFactory">The factory used to create the HTTP client for verification calls.</param>
/// <param name="logger">The logger.</param>
public class TenantVerifier(
    IOptionsMonitor<IngressConfig> config,
    IHttpClientFactory httpClientFactory,
    ILogger<TenantVerifier> logger) : ITenantVerifier
{
    /// <inheritdoc/>
    public async Task<bool> VerifyAsync(Guid tenantId)
    {
        var urlTemplate = config.CurrentValue.TenantVerification?.UrlTemplate;
        if (string.IsNullOrWhiteSpace(urlTemplate))
        {
            return true;
        }

        var url = urlTemplate.Replace("{tenantId}", tenantId.ToString());
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
