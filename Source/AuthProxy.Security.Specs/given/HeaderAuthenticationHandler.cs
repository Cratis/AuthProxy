// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// Authenticates a request that carries <see cref="SecurityHarness.AuthenticatedUserHeader"/>, standing in
/// for a valid session cookie.
/// </summary>
/// <remarks>
/// A header rather than a fixed always-authenticate scheme, so a single harness can serve both the specs
/// that ask what an anonymous caller can reach and the specs that ask what an authenticated caller can
/// escalate to. It is not the mechanism under test — every spec here treats "has a session" as given and
/// asks what else the caller can obtain by shaping the rest of the request.
/// </remarks>
/// <param name="options">The options monitor for authentication scheme options.</param>
/// <param name="logger">The logger factory.</param>
/// <param name="encoder">The URL encoder.</param>
public class HeaderAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    /// <summary>The scheme name the harness registers this under.</summary>
    public const string Scheme = "SecuritySpecScheme";

    /// <inheritdoc/>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var user = Request.Headers[SecurityHarness.AuthenticatedUserHeader].ToString();

        if (string.IsNullOrEmpty(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user),
                new Claim("oid", user),
                new Claim(ClaimTypes.Name, user),
            ],
            Scheme);

        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
    }
}
