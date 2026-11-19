// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Text;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.BearerRoutes.TokenExchange;

/// <summary>Uses only the configured Identity endpoint, with no redirects or unbounded response reads.</summary>
/// <param name="httpClientFactory">The non-redirecting named client factory.</param>
public sealed class IdentityTokenExchangeClient(IHttpClientFactory httpClientFactory) : ITokenExchangeClient
{
    /// <summary>The largest response body accepted, in bytes.</summary>
    public const int MaximumResponseSize = 16 * 1024;

    /// <inheritdoc/>
    public async Task<TokenExchangeResult> Exchange(C.BearerTokenExchange configuration, C.BearerTokenExchangeIssuer issuer, string token, string tenant, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!TokenExchangeConfigurationValidation.IsEndpoint(configuration.Endpoint)) return new(TokenExchangeVerdict.Refused);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(configuration.Timeout);
        try
        {
            using var request = Request(configuration, issuer, token, tenant);
            return await Send(request, deadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(TokenExchangeVerdict.Unavailable);
        }
        catch (HttpRequestException)
        {
            return new(TokenExchangeVerdict.Unavailable);
        }
        catch (IOException)
        {
            return new(TokenExchangeVerdict.Unavailable);
        }
    }

    static HttpRequestMessage Request(C.BearerTokenExchange configuration, C.BearerTokenExchangeIssuer issuer, string token, string tenant)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, configuration.Endpoint);
        var credentials = $"{Uri.EscapeDataString(configuration.ClientId)}:{Uri.EscapeDataString(configuration.ClientSecret)}";
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials)));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = token,
            ["subject_token_type"] = $"urn:ietf:params:oauth:token-type:{issuer.SubjectTokenType}",
            ["resource"] = configuration.Resource,
            ["scope"] = string.Join(' ', configuration.Scopes),
            ["tenant"] = tenant,
        });
        return request;
    }

    async Task<TokenExchangeResult> Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var client = httpClientFactory.CreateClient(BearerRouteDefaults.TokenExchangeHttpClientName);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        return await TokenExchangeResponse.Read(response, cancellationToken);
    }
}
