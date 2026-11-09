// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

sealed class BrowserSessionFixture : IDisposable
{
    internal const string Realm = "https://identity.example/realm/workforce";
    internal const string Subject = "11111111-1111-4111-8111-111111111111";
    internal const string Scheme = "identity";
    readonly ServiceProvider _services;

    internal BrowserSessionFixture()
    {
        Provider = new() { Name = "Identity", Type = C.OidcProviderType.CratisIdentity, Authority = Realm, ClientId = "browser-client" };
        CratisIdentityProfile.ApplyDefaults([Provider]);
        var authentication = new C.Authentication { OidcProviders = [Provider] };
        var monitor = Substitute.For<IOptionsMonitor<C.Authentication>>();
        monitor.CurrentValue.Returns(authentication);
        Options = new() { Authority = Realm, ClientId = Provider.ClientId };
        var oidc = Substitute.For<IOptionsMonitor<OpenIdConnectOptions>>();
        oidc.Get(Scheme).Returns(Options);
        var services = new ServiceCollection();
        services.AddSingleton(monitor);
        services.AddSingleton(oidc);
        services.AddSingleton<ICanonicalIdentityResolver>(new CanonicalIdentityResolver(monitor));
        _services = services.BuildServiceProvider();
        var original = new ClaimsPrincipal(new ClaimsIdentity([new("sub", Subject), new("auth_time", "1700000000"), new(ClaimTypes.Name, "Browser Example")], "oidc"));
        Principal = new CanonicalIdentityResolver(monitor).Resolve(original, Scheme, Realm, isFreshAuthentication: true).Principal!;
        Properties = new();
        Properties.Items[Cratis.AuthProxy.Authentication.AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = Scheme;
        Properties.Items[CanonicalSessionRegistrationFingerprint.StateKey] = CanonicalSessionRegistrationFingerprint.Create(Scheme, Provider, Options);
        Assert.True(FreshAuthenticationChallenge.ValidateOidc(Principal.Claims, Properties, DateTimeOffset.UtcNow));
        FreshAuthenticationChallenge.Stamp(Principal, Properties, oidc: true);
        Context = new() { RequestServices = _services, User = Principal };
        Settings = when_signing_with_explicit_trusted_context.Settings();
        Settings.TenantHeader = "x-workforce-tenant";
        var root = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        root.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = Settings } } });
        Accessor = new HttpContextAccessor { HttpContext = Context };
        Signer = new(root, TimeProvider.System, NullLogger<ForwardedIdentitySigner>.Instance, Accessor);
        Verified();
        Stamp();
        Authenticate();
    }

    internal C.OidcProvider Provider { get; }
    internal OpenIdConnectOptions Options { get; }
    internal ClaimsPrincipal Principal { get; }
    internal AuthenticationProperties Properties { get; }
    internal DefaultHttpContext Context { get; }
    internal C.ForwardedIdentitySigning Settings { get; }
    internal HttpContextAccessor Accessor { get; }
    internal ForwardedIdentitySigner Signer { get; }

    public void Dispose()
    {
        Accessor.HttpContext = null;
        _services.Dispose();
    }

    internal void Verified(string issuer = Realm, string subject = Subject, string idp = "https://upstream.example/", long time = 1700000000)
    {
        var handler = new JsonWebTokenHandler();
        var token = handler.ReadJsonWebToken(handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Claims = new Dictionary<string, object> { ["sub"] = subject, ["idp"] = idp, ["auth_time"] = time }
        }));
        VerifiedUpstreamClaims.Capture(Context, Scheme, token, token);
    }

    internal void Stamp() => BrowserSessionEvidence.Stamp(Context, Principal, Properties, Scheme);

    internal void Authenticate(string scheme = CookieAuthenticationDefaults.AuthenticationScheme, AuthenticationProperties? properties = null)
    {
        Context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(AuthenticateResult.Success(new AuthenticationTicket(Principal, properties ?? Properties, scheme))));
    }

    internal HttpRequestMessage Request()
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "https://backend.example/private?order=1");
        request.SetMicrosoftIdentityHeaders(Context.BuildClientPrincipal()!);
        request.Headers.Add(Headers.TenantId, "tenant-one");
        request.Headers.Add(Headers.ServiceId, "app");
        return request;
    }

    sealed class ResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}
