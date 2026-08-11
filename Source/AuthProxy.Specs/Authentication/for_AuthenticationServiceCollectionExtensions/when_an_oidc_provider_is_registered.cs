// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// The handshake only completes when the provider's callback carries the correlation cookie, and that
/// cookie is SameSite=Lax — which a browser attaches to a top-level GET and withholds from a cross-site
/// POST. The handler's own default response mode is form_post, exactly the callback shape the cookie can
/// never accompany: every OIDC sign-in and credential link died with "Correlation failed" and looped back
/// to provider selection. The registration must therefore pin the code flow's query response mode.
/// </summary>
public class when_an_oidc_provider_is_registered : given.an_ingress_authentication_builder
{
    protected override IDictionary<string, string?> Configuration => new Dictionary<string, string?>
    {
        [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Microsoft",
        [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.microsoftonline.com/common/v2.0",
        [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
    };

    void Because() => _options = ResolveOidcOptions("microsoft");

    [Fact] void should_return_the_authorization_code_in_a_top_level_get() => _options.ResponseMode.ShouldEqual(OpenIdConnectResponseMode.Query);
    [Fact] void should_keep_the_correlation_cookie_lax() => _options.CorrelationCookie.SameSite.ShouldEqual(SameSiteMode.Lax);
    [Fact] void should_keep_the_nonce_cookie_lax() => _options.NonceCookie.SameSite.ShouldEqual(SameSiteMode.Lax);
    [Fact] void should_keep_the_correlation_cookie_at_the_root_path() => _options.CorrelationCookie.Path.ShouldEqual("/");
    [Fact] void should_sign_in_through_the_cookie_scheme() => _options.SignInScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
