// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.OnBehalfSessions;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Tenancy.for_CredentialBindingMiddleware;

public class when_checking_a_credential : Specification
{
    [Theory]
    [InlineData("tenant-a", "tenant-b", false)]
    [InlineData("tenant-a", "tenant-a", true)]
    [InlineData("Tenant-A", "tenant-a", true)]
    [InlineData("tenant-a", "tenant-a ", false)]
    [InlineData(null, "tenant-b", true)]
    public async Task should_compare_a_protected_selection_before_selecting_a_namespace(string? selected, string addressed, bool allowed)
    {
        var context = Context();
        var cookie = new SelectedTenantCookie(new EphemeralDataProtectionProvider());
        if (selected is not null)
        {
            var writer = Context();
            cookie.TryWrite(writer, selected).ShouldBeTrue();
            context.Request.Headers.Cookie = writer.Response.Headers.SetCookie.ToString().Split(';')[0];
        }
        await Check(context, cookie, [new(addressed, C.TenantSourceIdentifierResolverType.Host)], allowed);
    }

    [Theory]
    [InlineData(C.TenantSourceIdentifierResolverType.Claim, false)]
    [InlineData(C.TenantSourceIdentifierResolverType.Default, true)]
    public async Task should_distinguish_a_bound_claim_from_an_unbound_default(C.TenantSourceIdentifierResolverType strategy, bool allowed) =>
        await Check(Context(), new(new EphemeralDataProtectionProvider()), [new("tenant-a", strategy), new("tenant-b", C.TenantSourceIdentifierResolverType.Route)], allowed);

    [Theory]
    [InlineData(ClientCredentialsDefaults.AuthenticationScheme, false)]
    [InlineData("another-scheme", true)]
    public async Task should_only_trust_client_credentials_tenant_claims_from_their_scheme(string scheme, bool allowed)
    {
        var context = Context();
        context.User = new(new ClaimsIdentity([new Claim(ClientCredentialsDefaults.TenantClaimType, "tenant-a")], scheme));
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("tenant-b", C.TenantSourceIdentifierResolverType.Host)], allowed);
    }

    [Theory]
    [InlineData("tenant-b", false)]
    [InlineData("tenant-a", true)]
    public async Task should_use_only_the_on_behalf_tenant(string target, bool allowed)
    {
        var context = Context();
        context.SetOnBehalf(new OnBehalfContext(
            new("session", new("oidc", "actor", "person"), "tenant-a", "represented", "issue", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(5)),
            new ClientPrincipal { UserId = "represented" },
            "actor",
            Substitute.For<IOnBehalfAttestations>()));
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("actor-tenant", C.TenantSourceIdentifierResolverType.Claim), new(target, C.TenantSourceIdentifierResolverType.Host)], allowed);
    }

    [Theory]
    [InlineData("/.cratis/select-tenant")]
    [InlineData("/.cratis/login")]
    public async Task should_allow_pre_tenant_flows(string path)
    {
        var context = Context();
        context.Request.Path = path;
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("tenant-a", C.TenantSourceIdentifierResolverType.Claim), new("tenant-b", C.TenantSourceIdentifierResolverType.Host)], true);
    }

    [Theory]
    [InlineData(Cookies.Registration)]
    [InlineData(Cookies.InviteToken)]
    public async Task should_not_exempt_a_pending_cookie(string name)
    {
        var context = Context();
        context.Request.Headers.Cookie = $"{name}=x";
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("tenant-a", C.TenantSourceIdentifierResolverType.Claim), new("tenant-b", C.TenantSourceIdentifierResolverType.Host)], false);
    }

    [Theory]
    [InlineData("tenant-b", false)]
    [InlineData("Tenant-A", true)]
    public async Task should_check_the_effective_default_against_a_token_binding(string target, bool allowed)
    {
        var context = Context();
        context.User = new(new ClaimsIdentity([new Claim(ClientCredentialsDefaults.TenantClaimType, "tenant-a")], ClientCredentialsDefaults.AuthenticationScheme));
        await Check(context, new(new EphemeralDataProtectionProvider()), [new(target, C.TenantSourceIdentifierResolverType.Default)], allowed, checkEffectiveTenant: true);
    }

    [Fact]
    public async Task should_ignore_anonymous_and_legacy_selections()
    {
        var context = Context();
        context.Request.Headers.Cookie = $"{Cookies.Tenant}=tenant-a";
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("tenant-b", C.TenantSourceIdentifierResolverType.Host)], true);
        context.User = new();
        await Check(context, new(new EphemeralDataProtectionProvider()), [new("tenant-a", C.TenantSourceIdentifierResolverType.Claim), new("tenant-b", C.TenantSourceIdentifierResolverType.Host)], true);
    }

    static DefaultHttpContext Context() => new()
    {
        User = new(new ClaimsIdentity([new Claim("sub", "alice"), new Claim("identity_provider", "oidc")], "test")),
    };

    static async Task Check(DefaultHttpContext context, SelectedTenantCookie cookie, TenantResolutionResult[] resolutions, bool allowed, bool checkEffectiveTenant = false)
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy { TenantResolutions = [new() { Strategy = C.TenantSourceIdentifierResolverType.Host }] });
        var resolver = Substitute.For<ITenantResolver>();
        resolver.ResolveEach(context).Returns(resolutions);
        resolver.TryResolve(context, out Arg.Any<TenantResolutionResult>()).Returns(call =>
        {
            call[1] = resolutions[0];
            return true;
        });
        var errors = Substitute.For<IErrorPageProvider>();
        var called = false;
        var middleware = new CredentialBindingMiddleware(
            _ =>
            {
                called = true;
                return Task.CompletedTask;
            },
            options,
            resolver,
            cookie,
            errors,
            Substitute.For<ILogger<CredentialBindingMiddleware>>(),
            checkEffectiveTenant);
        await middleware.InvokeAsync(context);
        called.ShouldEqual(allowed);
        context.Items.ContainsKey(TenancyMiddleware.TenantIdItemKey).ShouldBeFalse();
        if (!allowed)
        {
            await errors.Received(1).WriteErrorPageAsync(context, WellKnownPageNames.Forbidden, StatusCodes.Status403Forbidden);
            context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        }
    }
}
