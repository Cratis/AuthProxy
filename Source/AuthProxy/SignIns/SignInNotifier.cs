// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.SignIns;

/// <summary>
/// Posts a completed sign-in to the application's configured <see cref="C.SignIn.NotifyUrl"/>. It mirrors the
/// invite exchange (<see cref="Invites.InviteMiddleware"/>) and credential-link callback
/// (<see cref="Links.LinkSubjectExchanger"/>): the subject and identity provider are read from the freshly
/// authenticated principal, enriched with the approximate location and browser derived from the request, and
/// posted server-to-server. Recording a sign-in must never break the sign-in, so every failure is swallowed
/// and reported through the returned <see cref="SignInNotificationResult"/>.
/// </summary>
/// <param name="config">The auth proxy configuration monitor.</param>
/// <param name="locationResolver">The resolver for the request's approximate location.</param>
/// <param name="httpClientFactory">The HTTP client factory used for the notification call.</param>
/// <param name="logger">The logger.</param>
public class SignInNotifier(
    IOptionsMonitor<C.AuthProxy> config,
    IClientLocationResolver locationResolver,
    IHttpClientFactory httpClientFactory,
    ILogger<SignInNotifier> logger) : ISignInNotifier
{
    /// <inheritdoc/>
    public async Task<SignInNotificationResult> Notify(HttpContext context, ClaimsPrincipal? principal)
    {
        var notifyUrl = config.CurrentValue.SignIn?.NotifyUrl;
        if (string.IsNullOrWhiteSpace(notifyUrl))
        {
            return SignInNotificationResult.Skipped;
        }

        var subject = principal?.FindFirst("sub")?.Value
            ?? principal?.FindFirst("oid")?.Value
            ?? principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? principal?.FindFirst("id")?.Value
            ?? string.Empty;

        if (string.IsNullOrWhiteSpace(subject))
        {
            logger.SignInSubjectMissing();
            return SignInNotificationResult.Failed;
        }

        var identityProvider = principal?.FindFirst("iss")?.Value
            ?? principal?.FindFirst("identity_provider")?.Value
            ?? principal?.FindFirst("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider")?.Value
            ?? principal?.Identity?.AuthenticationType
            ?? string.Empty;

        var location = locationResolver.Resolve(context);
        var userAgent = UserAgentParser.Parse(context.Request.Headers.UserAgent.ToString());

        using var client = httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, notifyUrl)
        {
            Content = JsonContent.Create(new
            {
                subject,
                identityProvider,
                ipAddress = location.IpAddress,
                location = location.Location,
                browser = userAgent.Browser,
                operatingSystem = userAgent.OperatingSystem,
                userAgent = userAgent.Raw,
            }),
        };

        HttpResponseMessage response;
        try
        {
            response = await client.SendAsync(request);
        }
        catch (Exception ex)
        {
            logger.FailedToCallSignInNotifyEndpoint(ex, notifyUrl);
            return SignInNotificationResult.Failed;
        }

        if (!response.IsSuccessStatusCode)
        {
            logger.SignInNotifyEndpointFailed((int)response.StatusCode);
            return SignInNotificationResult.Failed;
        }

        logger.SignInNotified(subject);
        return SignInNotificationResult.Notified;
    }
}
