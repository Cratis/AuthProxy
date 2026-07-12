// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Calls the configured downstream verification endpoint for the client-credentials flow.
/// </summary>
/// <param name="httpClientFactory">Creates outbound HTTP clients for verification requests.</param>
public class ClientCredentialsVerifier(
    IHttpClientFactory httpClientFactory)
{
    static readonly JsonSerializerOptions _responseSerializerOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Verifies the supplied client credentials against the configured downstream service.
    /// </summary>
    /// <param name="service">The target service configuration.</param>
    /// <param name="clientId">The client identifier supplied to AuthProxy.</param>
    /// <param name="clientSecret">The client secret supplied to AuthProxy.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The result of the downstream verification request.</returns>
    public async Task<ClientCredentialsVerificationResult> VerifyAsync(
        ConfiguredClientCredentialsService service,
        string clientId,
        string clientSecret,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, service.VerificationUri)
        {
            Content = JsonContent.Create(new ClientCredentialsVerificationRequest(
                service.Name,
                service.RoutePrefix,
                clientId,
                clientSecret))
        };

        try
        {
            using var response = await httpClientFactory.CreateClient(nameof(ClientCredentialsVerifier))
                .SendAsync(request, cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                var tenant = await TryReadTenantAsync(response, cancellationToken);
                return new(ClientCredentialsVerificationStatus.Succeeded, response.StatusCode, tenant);
            }

            return (int)response.StatusCode >= 500
                ? new(ClientCredentialsVerificationStatus.Failed, response.StatusCode)
                : new(ClientCredentialsVerificationStatus.Rejected, response.StatusCode);
        }
        catch (HttpRequestException)
        {
            return new(ClientCredentialsVerificationStatus.Failed, HttpStatusCode.BadGateway);
        }
    }

    static async Task<string?> TryReadTenantAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            var body = await response.Content.ReadFromJsonAsync<ClientCredentialsVerificationResponseBody>(_responseSerializerOptions, cancellationToken);
            return string.IsNullOrWhiteSpace(body?.Tenant) ? null : body.Tenant;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
