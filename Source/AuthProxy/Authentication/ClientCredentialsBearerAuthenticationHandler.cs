// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Authenticates AuthProxy-issued bearer tokens created through the back-channel client-credentials flow.
/// </summary>
/// <param name="options">The authentication scheme options monitor.</param>
/// <param name="logger">The logger factory.</param>
/// <param name="encoder">The URL encoder.</param>
/// <param name="serviceResolver">Resolves which configured service the current request targets.</param>
/// <param name="tokenProtector">Validates AuthProxy-issued bearer tokens.</param>
public class ClientCredentialsBearerAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ClientCredentialsServiceResolver serviceResolver,
    ClientCredentialsTokenProtector tokenProtector)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    /// <inheritdoc/>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!TryGetBearerToken(out var token))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!TryGetValidatedPayload(token, out var payload))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!serviceResolver.TryResolveForRequest(Request, out var service))
        {
            return Task.FromResult(AuthenticateResult.Fail("Unable to resolve the target service for the bearer token."));
        }

        if (!string.Equals(service.Name, payload.Service, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(service.RoutePrefix, payload.RoutePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(AuthenticateResult.Fail("The bearer token is not valid for the requested service or route."));
        }

        var claims = new List<Claim>
        {
            new("sub", payload.ClientId),
            new("client_id", payload.ClientId),
            new("name", payload.ClientId),
            new(ClaimTypes.Name, payload.ClientId),
            new(ClientCredentialsDefaults.ServiceClaimType, payload.Service),
            new(ClientCredentialsDefaults.RoutePrefixClaimType, payload.RoutePrefix),
            new("amr", ClientCredentialsDefaults.GrantType),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    bool TryGetBearerToken(out string token)
    {
        token = string.Empty;

        var authorization = Request.Headers.Authorization.ToString();
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        token = authorization["Bearer ".Length..].Trim();
        return !string.IsNullOrWhiteSpace(token);
    }

    /// <summary>
    /// Gets the token payload validated earlier by the composite scheme selector, when present,
    /// to avoid unprotecting the same token twice. Falls back to validating it directly so the
    /// handler also works when invoked without going through the composite scheme (e.g. in specs).
    /// </summary>
    /// <param name="token">The bearer token to validate.</param>
    /// <param name="payload">The resolved token payload.</param>
    /// <returns><see langword="true"/> if a payload was found or validated; otherwise <see langword="false"/>.</returns>
    bool TryGetValidatedPayload(string token, out ClientCredentialsTokenPayload payload)
    {
        if (Context.Items.TryGetValue(ClientCredentialsDefaults.ValidatedTokenPayloadItemKey, out var cached)
            && cached is ClientCredentialsTokenPayload cachedPayload)
        {
            payload = cachedPayload;
            return true;
        }

        return tokenProtector.TryValidate(token, out payload);
    }
}
