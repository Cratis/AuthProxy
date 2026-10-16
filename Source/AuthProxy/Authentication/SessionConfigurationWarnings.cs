// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Describes the session cookie settings that are valid but risky, so startup can say so without refusing to run.
/// </summary>
/// <remarks>
/// <see cref="SessionConfigurationValidator"/> refuses what cannot work. These are the things that work and
/// still deserve a second look.
/// </remarks>
public static class SessionConfigurationWarnings
{
    const string SecurePrefix = "__Secure-";

    /// <summary>
    /// Describes the warnings that apply to a session configuration.
    /// </summary>
    /// <param name="session">The session configuration.</param>
    /// <param name="allowedHosts">The host names the ASP.NET host filter accepts; <c language="text">*</c> or none accepts every host.</param>
    /// <returns>One message per warning, empty when there is nothing to warn about.</returns>
    public static IEnumerable<string> Describe(C.Session session, IEnumerable<string> allowedHosts)
    {
        if (SessionCookie.DomainOf(session) is not null
            && (!allowedHosts.Any() || allowedHosts.Any(_ => _.Trim() == "*")))
        {
            yield return $"{C.Session.SectionKey}:{nameof(C.Session.CookieDomain)} is set while AllowedHosts accepts every host. The shared session cookie makes the Host header a more valuable thing to spoof, so list the host names the ingress forwards in AllowedHosts.";
        }

        if (SessionCookie.NameOf(session).StartsWith(SecurePrefix, StringComparison.OrdinalIgnoreCase))
        {
            yield return $"{C.Session.SectionKey}:{nameof(C.Session.CookieName)} uses the {SecurePrefix} prefix, which browsers only accept over HTTPS. The session cookie is marked Secure only when the request is HTTPS, so a plain HTTP deployment would lose its session.";
        }
    }
}
