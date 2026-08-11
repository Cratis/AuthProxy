// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Some providers mandate a form POST callback — Apple whenever the name or email scopes are requested. A
/// cross-site POST only ever carries SameSite=None cookies, so opting a provider into form_post must also
/// switch that provider's handshake cookies to None+Secure or its callbacks would fail exactly the way the
/// default used to.
/// </summary>
public class when_an_oidc_provider_opts_into_form_post : given.an_ingress_authentication_builder
{
    protected override IDictionary<string, string?> Configuration => new Dictionary<string, string?>
    {
        [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Apple",
        [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://appleid.apple.com",
        [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-id",
        [$"{C.Authentication.SectionKey}:OidcProviders:0:ResponseMode"] = nameof(C.OidcResponseMode.FormPost),
    };

    void Because() => _options = ResolveOidcOptions("apple");

    [Fact] void should_return_the_authorization_code_in_a_form_post() => _options.ResponseMode.ShouldEqual(OpenIdConnectResponseMode.FormPost);
    [Fact] void should_send_the_correlation_cookie_cross_site() => _options.CorrelationCookie.SameSite.ShouldEqual(SameSiteMode.None);
    [Fact] void should_require_https_for_the_correlation_cookie() => _options.CorrelationCookie.SecurePolicy.ShouldEqual(CookieSecurePolicy.Always);
    [Fact] void should_send_the_nonce_cookie_cross_site() => _options.NonceCookie.SameSite.ShouldEqual(SameSiteMode.None);
    [Fact] void should_require_https_for_the_nonce_cookie() => _options.NonceCookie.SecurePolicy.ShouldEqual(CookieSecurePolicy.Always);
    [Fact] void should_sign_in_through_the_cookie_scheme() => _options.SignInScheme.ShouldEqual(CookieAuthenticationDefaults.AuthenticationScheme);
}
