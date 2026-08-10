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

    /// <summary>
    /// The header a spec sends to give its caller extra claims, as <c>type=value</c> pairs separated by
    /// semicolons.
    /// </summary>
    /// <remarks>
    /// Everything the first authorization gate decides on is a claim, so a spec asking what a caller can
    /// reach has to be able to say which claims they carry — including none, which is the interesting one.
    /// A caller sending no such header is unchanged, so this is invisible to every spec that predates it.
    /// </remarks>
    public const string ClaimsHeader = "X-Security-Spec-Claims";

    /// <inheritdoc/>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var user = Request.Headers[SecurityHarness.AuthenticatedUserHeader].ToString();

        if (string.IsNullOrEmpty(user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user),
            new("oid", user),
            new(ClaimTypes.Name, user),
        };

        claims.AddRange(DeclaredClaims());

        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme)), Scheme)));
    }

    IEnumerable<Claim> DeclaredClaims()
    {
        var declared = Request.Headers[ClaimsHeader].ToString();

        foreach (var pair in declared.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0)
            {
                yield return new Claim(pair[..separator], pair[(separator + 1)..]);
            }
        }
    }
}
