// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Admission;

/// <summary>
/// Reads a presented capability, has it verified, and issues the entry transaction when it admits.
/// </summary>
/// <param name="verifier">The verifier deciding whether a capability admits.</param>
/// <param name="protector">The protector sealing the entry transaction into the browser.</param>
/// <param name="timeProvider">The source of the current time.</param>
/// <remarks>
/// The capability is read from the request body and from nowhere else. A path segment, a query parameter,
/// a header and a cookie are all places a value ends up written into an access log, a proxy's cache key or
/// a browser's history, and a bearer value that admits a caller has no business in any of them.
/// </remarks>
public class CapabilityAdmission(
    ICapabilityVerifier verifier,
    IEntryTransactionProtector protector,
    TimeProvider timeProvider) : ICapabilityAdmission
{
    /// <inheritdoc/>
    public async Task<bool> TryAdmit(HttpContext context, C.AuthProxy config)
    {
        var settings = config.Admission.Capability;
        if (settings is null || !HttpMethods.IsPost(context.Request.Method))
        {
            return false;
        }

        var capability = await CapabilityBody.TryRead(context.Request, settings.MaximumLength, context.RequestAborted);
        if (capability is null)
        {
            return false;
        }

        var presentation = new CapabilityPresentation(capability, CreateOpaqueValue(), CreateOpaqueValue());
        var verification = await verifier.Verify(presentation, context.RequestAborted);
        if (!verification.IsAdmitted)
        {
            return false;
        }

        Issue(context, config, presentation, verification);

        return true;
    }

    /// <summary>
    /// Creates a cryptographically random 256-bit opaque value.
    /// </summary>
    /// <returns>A hexadecimal opaque value.</returns>
    static string CreateOpaqueValue() => RandomNumberGenerator.GetHexString(64, lowercase: true);

    /// <summary>
    /// Writes the sealed entry transaction to the browser and answers the presentation.
    /// </summary>
    /// <param name="context">The current <see cref="HttpContext"/>.</param>
    /// <param name="config">The auth proxy configuration to read.</param>
    /// <param name="presentation">The presentation that was admitted.</param>
    /// <param name="verification">The verifier's answer about it.</param>
    /// <remarks>
    /// The answer carries no body at all. What the browser needs is the cookie, and a body would be one
    /// more thing that could differ between deployments and describe them.
    /// </remarks>
    void Issue(HttpContext context, C.AuthProxy config, CapabilityPresentation presentation, CapabilityVerification verification)
    {
        var lifetime = config.Admission.EntryLifetime;
        var transaction = new EntryTransaction(
            presentation.Transaction,
            presentation.Challenge,
            timeProvider.GetUtcNow().Add(lifetime),
            verification.Context);

        context.Response.Cookies.Append(Cookies.EntryTransaction, protector.Protect(transaction), new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = context.Request.IsHttps,
            Path = "/",
            MaxAge = lifetime,
        });

        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }
}
