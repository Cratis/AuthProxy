// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.Identity;

namespace Cratis.AuthProxy.SignInCallbacks;

/// <summary>
/// Posts a sign-in callback to a service, the way AuthProxy would present the user on a proxied request.
/// </summary>
/// <param name="httpClientFactory">The HTTP client factory.</param>
/// <param name="signer">The forwarded-identity signer.</param>
/// <param name="logger">The logger.</param>
public class SignInCallbackSender(IHttpClientFactory httpClientFactory, IForwardedIdentitySigner signer, ILogger<SignInCallbackSender> logger) : ISignInCallbackSender
{
    static readonly JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.Web);

    /// <inheritdoc/>
    public async Task<bool> Send(SignInCallbackRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using var message = Build(request);
            var signing = signer.Sign(message, new(ForwardedIdentityFlow.SignInCallback, request.ServiceName));
            if (signing is ForwardedIdentitySigningOutcome.Refused or ForwardedIdentitySigningOutcome.NotIdentityBearing)
            {
                logger.SignInCallbackCouldNotBeSigned(request.Kind, request.ServiceName);
                return false;
            }
            using var client = signing == ForwardedIdentitySigningOutcome.SignatureCreated
                ? httpClientFactory.CreateClient(ForwardedIdentityServiceCollectionExtensions.HttpClientName)
                : httpClientFactory.CreateClient();
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (request.Timeout > TimeSpan.Zero)
            {
                timeoutSource.CancelAfter(request.Timeout);
            }

            using var response = await client.SendAsync(message, timeoutSource.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.CallbackRefused(request.ServiceName, request.Kind, (int)response.StatusCode);
                return false;
            }

            logger.CallbackDelivered(request.ServiceName, request.Kind);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            logger.CallbackTimedOut(request.ServiceName, request.Kind, request.Timeout);
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            logger.CallbackFailed(ex, request.ServiceName, request.Kind);
            return false;
        }
    }

    static HttpRequestMessage Build(SignInCallbackRequest request)
    {
        var principal = request.Principal;
        var body = new SignInCallbackBody(
            request.Kind.ToString(),
            principal.UserId,
            ClaimValue(principal, "name", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name") ?? string.Empty,
            ClaimValue(principal, "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress") ?? string.Empty,
            principal.IdentityProvider,
            string.IsNullOrWhiteSpace(request.Tenant) ? null : request.Tenant,
            request.Occurred.ToUniversalTime());

        var message = new HttpRequestMessage(HttpMethod.Post, request.Url)
        {
            Content = JsonContent.Create(body, options: _serializerOptions)
        };

        // The identity headers are the ones a proxied request carries, so the application reads the user the way
        // it always does. The marker says the call is AuthProxy's own; a caller cannot send it, because AuthProxy
        // strips it from every inbound request.
        message.SetMicrosoftIdentityHeaders(principal);
        message.Headers.Add(Headers.SignInCallback, request.Kind.ToString());

        var service = HeaderValue.ToTransportValue(request.ServiceName);
        message.Headers.Add(Headers.ServiceId, service);
        message.Headers.Add(Headers.LegacyServiceId, service);

        if (!string.IsNullOrWhiteSpace(request.Tenant))
        {
            var tenant = HeaderValue.ToTransportValue(request.Tenant);
            message.Headers.Add(Headers.TenantId, tenant);
            message.Headers.Add(Headers.LegacyTenantId, tenant);
        }

        if (!string.IsNullOrEmpty(request.Secret))
        {
            message.Headers.Add(Headers.SignInCallbackSecret, request.Secret);
        }

        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return message;
    }

    static string? ClaimValue(ClientPrincipal principal, params string[] types) =>
        principal.Claims
            .Where(_ => types.Contains(_.Type, StringComparer.Ordinal) && !string.IsNullOrWhiteSpace(_.Value))
            .Select(_ => _.Value)
            .FirstOrDefault();
}
