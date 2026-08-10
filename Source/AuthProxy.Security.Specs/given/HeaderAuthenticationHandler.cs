// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Claims;
using System.Text;
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

    /// <summary>
    /// The header a spec sends to give its caller claims whose values are not US-ASCII — the same
    /// <c>type=value</c> pair format as <see cref="ClaimsHeader"/>, base64-encoded UTF-8.
    /// </summary>
    /// <remarks>
    /// A spec cannot declare a name like <c>Søren Wærstad</c> through <see cref="ClaimsHeader"/>, because
    /// that header is itself subject to the very limitation these specs exist to prove is handled. Encoding
    /// it here keeps the harness honest: the spec's own transport is a spec concern, and nothing about the
    /// production path is relaxed to accommodate it — the claim arrives at
    /// <c>BuildClientPrincipal</c> as an ordinary .NET string, exactly as a real provider's would.
    /// </remarks>
    public const string EncodedClaimsHeader = "X-Security-Spec-Claims-Encoded";

    /// <summary>
    /// Encodes claim declarations so a spec can put them on <see cref="EncodedClaimsHeader"/>.
    /// </summary>
    /// <param name="declarations">The <c>type=value</c> pairs, separated by semicolons.</param>
    /// <returns>The declarations in the form the header carries.</returns>
    public static string EncodeClaims(string declarations) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(declarations));

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

    static IEnumerable<Claim> Parse(string declared)
    {
        foreach (var pair in declared.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0)
            {
                yield return new Claim(pair[..separator], pair[(separator + 1)..]);
            }
        }
    }

    IEnumerable<Claim> DeclaredClaims() =>
        Parse(Request.Headers[ClaimsHeader].ToString()).Concat(Parse(EncodedDeclarations()));

    string EncodedDeclarations()
    {
        var encoded = Request.Headers[EncodedClaimsHeader].ToString();
        if (string.IsNullOrEmpty(encoded))
        {
            return string.Empty;
        }

        var octets = new byte[encoded.Length];

        return Convert.TryFromBase64String(encoded, octets, out var written)
            ? Encoding.UTF8.GetString(octets, 0, written)
            : string.Empty;
    }
}
