// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SessionTermination;

public class when_terminating_a_session : Specification
{
    const string AuthenticationCookie = ".Cratis.AuthProxy.Auth.v2";
    const string AuthenticationChunkOne = $"{AuthenticationCookie}C1";
    const string AuthenticationChunkTwo = $"{AuthenticationCookie}C2";
    const string CorrelationCookie = $"{Cookies.CorrelationPrefix}provider.state";
    const string NonceCookie = $"{Cookies.NoncePrefix}provider.state";
    const string AdditionalCookie = "shared-session";

    DefaultHttpContext _context;
    ServiceProvider _services;

    void Establish()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services
            .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options => options.Cookie.Name = AuthenticationCookie);

        _services = services.BuildServiceProvider();
        _context = new DefaultHttpContext
        {
            RequestServices = _services
        };
        _context.Request.Scheme = "https";
        _context.Request.Path = "/identity-check";
        _context.Request.Headers.Cookie = string.Join("; ",
        [
            $"{AuthenticationCookie}=chunks-2",
            $"{AuthenticationChunkOne}=first",
            $"{AuthenticationChunkTwo}=second",
            $"{Cookies.Identity}=identity",
            $"{Cookies.IdentityAuthorization}=authorization",
            $"{Cookies.Tenant}=tenant",
            $"{Cookies.Tenants}=tenants",
            $"{Cookies.InviteToken}=invite",
            $"{Cookies.InvitationEntryState}=invite-state",
            $"{Cookies.Registration}=registration",
            $"{Cookies.Providers}=providers",
            $"{CorrelationCookie}=correlation",
            $"{NonceCookie}=nonce",
            $"{AdditionalCookie}=additional",
            $"{Cookies.EntryTransaction}=entry",
            $"{Cookies.LogoutRedirect}=logout"
        ]);
    }

    async Task Because() => await SessionTermination.SignOutAndClearCookies(
        _context,
        new C.Logout
        {
            AdditionalCookies = [new C.LogoutCookie { Name = AdditionalCookie }]
        });

    void Destroy() => _services.Dispose();

    [Fact] void should_expire_the_authentication_cookie() => WasDeleted(AuthenticationCookie).ShouldBeTrue();
    [Fact] void should_expire_the_first_authentication_cookie_chunk() => WasDeleted(AuthenticationChunkOne).ShouldBeTrue();
    [Fact] void should_expire_the_second_authentication_cookie_chunk() => WasDeleted(AuthenticationChunkTwo).ShouldBeTrue();
    [Fact] void should_expire_the_identity_cookie() => WasDeleted(Cookies.Identity).ShouldBeTrue();
    [Fact] void should_expire_the_identity_authorization_cookie() => WasDeleted(Cookies.IdentityAuthorization).ShouldBeTrue();
    [Fact] void should_expire_the_selected_tenant_cookie() => WasDeleted(Cookies.Tenant).ShouldBeTrue();
    [Fact] void should_expire_the_selectable_tenants_cookie() => WasDeleted(Cookies.Tenants).ShouldBeTrue();
    [Fact] void should_expire_the_invite_cookie() => WasDeleted(Cookies.InviteToken).ShouldBeTrue();
    [Fact] void should_expire_the_invitation_entry_cookie() => WasDeleted(Cookies.InvitationEntryState).ShouldBeTrue();
    [Fact] void should_expire_the_registration_cookie() => WasDeleted(Cookies.Registration).ShouldBeTrue();
    [Fact] void should_expire_the_provider_cookie() => WasDeleted(Cookies.Providers).ShouldBeTrue();
    [Fact] void should_expire_the_correlation_cookie() => WasDeleted(CorrelationCookie).ShouldBeTrue();
    [Fact] void should_expire_the_nonce_cookie() => WasDeleted(NonceCookie).ShouldBeTrue();
    [Fact] void should_expire_the_configured_additional_cookie() => WasDeleted(AdditionalCookie).ShouldBeTrue();
    [Fact] void should_retain_the_entry_cookie() => WasDeleted(Cookies.EntryTransaction).ShouldBeFalse();
    [Fact] void should_retain_the_logout_redirect_cookie() => WasDeleted(Cookies.LogoutRedirect).ShouldBeFalse();

    bool WasDeleted(string name) =>
        _context.Response.Headers.SetCookie.Any(_ => _?.StartsWith($"{name}=;", StringComparison.Ordinal) == true);
}
