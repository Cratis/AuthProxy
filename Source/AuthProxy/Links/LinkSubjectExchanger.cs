// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Posts the freshly authenticated subject of a link challenge to the application's configured
/// <see cref="C.Link.ExchangeUrl"/>. It mirrors the invite-exchange call
/// (<see cref="Invites.InviteMiddleware"/>): the subject and identity provider are read from the second
/// provider's principal and posted with the one-time link token as the bearer credential. Crucially, the
/// new identity is never signed in, so the user's primary session is preserved.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="httpClientFactory">The HTTP client factory used for the exchange call.</param>
/// <param name="logger">The logger.</param>
public class LinkSubjectExchanger(
    IOptionsMonitor<C.AuthProxy> config,
    IHttpClientFactory httpClientFactory,
    ILogger<LinkSubjectExchanger> logger) : ILinkSubjectExchanger
{
    /// <inheritdoc/>
    public async Task<LinkExchangeResult> Exchange(ClaimsPrincipal? principal, AuthenticationProperties properties)
    {
        var exchangeUrl = config.CurrentValue.Link?.ExchangeUrl;
        if (string.IsNullOrWhiteSpace(exchangeUrl))
        {
            logger.LinkExchangeUrlNotConfigured();
            return LinkExchangeResult.Failed;
        }

        if (!properties.Items.TryGetValue(LinkMiddleware.LinkTokenPropertyKey, out var linkToken)
            || string.IsNullOrWhiteSpace(linkToken))
        {
            logger.LinkTokenMissing();
            return LinkExchangeResult.Failed;
        }

        var subject = principal?.FindFirst("sub")?.Value
            ?? principal?.FindFirst("oid")?.Value
            ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal?.FindFirst("id")?.Value
            ?? string.Empty;

        var identityProvider = principal?.FindFirst("iss")?.Value
            ?? principal?.FindFirst("identity_provider")?.Value
            ?? principal?.FindFirst("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider")?.Value
            ?? principal?.Identity?.AuthenticationType
            ?? string.Empty;

        if (string.IsNullOrWhiteSpace(subject))
        {
            logger.LinkSubjectMissing();
            return LinkExchangeResult.Failed;
        }

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, exchangeUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", linkToken);
        request.Content = JsonContent.Create(new { subject, identityProvider });

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.FailedToCallLinkExchangeEndpoint(ex, exchangeUrl);
            return LinkExchangeResult.Failed;
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.LinkExchangeEndpointFailed((int)response.StatusCode);
            return LinkExchangeResult.Failed;
        }

        logger.LinkExchangedSuccessfully();
        return LinkExchangeResult.Success;
    }
}
