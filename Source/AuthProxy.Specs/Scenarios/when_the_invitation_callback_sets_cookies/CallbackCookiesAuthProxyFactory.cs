// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Scenarios.when_the_invitation_callback_sets_cookies;

/// <summary>
/// The real OIDC callback pipeline configured the way the reporter of issue #225 runs it: a service that requires
/// identity verification, so the identity, authorization and tenant machinery is wired in.
/// </summary>
public class CallbackCookiesAuthProxyFactory : OidcCallbackAuthProxyFactory
{
    /// <summary>Gets the origin the browser addresses.</summary>
    public virtual Uri BrowserBase => new("http://localhost");

    /// <summary>Gets the session cookie domain, or <see langword="null"/> for a host-only cookie.</summary>
    protected virtual string? CookieDomain => null;

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        foreach (var (key, value) in new Dictionary<string, string>
        {
            [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = "http://app.test/",
            [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = "http://app.test/",
            [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerification"] = nameof(C.IdentityVerificationMode.Required),
            [$"{C.AuthProxy.SectionKey}:Services:app:IdentityVerificationTimeout"] = "00:00:05",
        })
        {
            builder.UseSetting(key, value);
        }

        if (CookieDomain is not null)
        {
            builder.UseSetting($"{C.Session.SectionKey}:{nameof(C.Session.CookieDomain)}", CookieDomain);
        }
    }
}
