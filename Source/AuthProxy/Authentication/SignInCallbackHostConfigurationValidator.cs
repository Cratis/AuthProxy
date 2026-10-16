// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ReverseProxy;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Validates the fixed sign-in callback host at startup.
/// </summary>
/// <remarks>
/// A callback host only works when the session cookie is valid on it and on every host the person returns to, so it
/// is refused unless a cookie domain is set and covers it. A misconfiguration would otherwise surface as a sign-in
/// that completes and lands the person signed out.
/// </remarks>
public class SignInCallbackHostConfigurationValidator : IValidateOptions<C.AuthProxy>
{
    /// <inheritdoc/>
    public ValidateOptionsResult Validate(string? name, C.AuthProxy options)
    {
        var configured = options.SignIn?.CallbackHost;
        if (string.IsNullOrEmpty(configured))
        {
            return ValidateOptionsResult.Success;
        }

        var key = $"{C.AuthProxy.SectionKey}:SignIn:{nameof(C.SignIn.CallbackHost)}";
        var domainKey = $"{C.Session.SectionKey}:{nameof(C.Session.CookieDomain)}";

        if (!ServiceRoutes.TryParseHost(configured, out var host))
        {
            return ValidateOptionsResult.Fail($"{key} '{configured}' is not a host name with an optional port, such as auth.example.com or auth.example.com:8443. Wildcards, schemes and paths are not allowed.");
        }

        var domain = SessionCookie.DomainOf(options.Session);
        if (domain is null)
        {
            return ValidateOptionsResult.Fail($"{key} is set but {domainKey} is not. The session has to be valid on the callback host and on the host the person returns to, which takes a session cookie shared across hosts. Set {domainKey}, or leave the callback host unset.");
        }

        // The domain's own failures are reported by the session validator; there is nothing to compare against here.
        if (CookieDomainScope.Evaluate(domain, out var normalized) != CookieDomainRejection.None)
        {
            return ValidateOptionsResult.Success;
        }

        return CookieDomainScope.Covers(normalized, host.Host)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail($"{key} '{configured}' is outside {domainKey} '{domain}'. The session cookie would not be sent to it, so a person signing in there would come back signed out.");
    }
}
