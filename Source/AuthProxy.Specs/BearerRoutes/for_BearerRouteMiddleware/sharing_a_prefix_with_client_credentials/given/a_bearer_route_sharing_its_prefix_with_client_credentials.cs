// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware.sharing_a_prefix_with_client_credentials.given;

/// <summary>
/// A bearer route on /api of service portal, which also issues client-credentials tokens for /api.
/// Its collaborators record every call, so a spec can show which rules judged a credential.
/// </summary>
public abstract class a_bearer_route_sharing_its_prefix_with_client_credentials : Specification
{
    protected const string Prefix = "/api";
    protected const string ServiceName = "portal";
    protected const string ResourceMetadataUrl = "https://portal.example.test/.well-known/oauth-protected-resource/api";
    protected const string ValidExternalToken = "eyJhbGciOiJSUzI1NiJ9.eyJ2YWxpZCI6dHJ1ZX0.c2ln";
    protected const string InvalidExternalToken = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln";

    protected IDataProtectionProvider DataProtection { get; } = new EphemeralDataProtectionProvider();

    protected Authentication.for_ClientCredentialsTokenProtector.given.ManualTime Clock { get; } = new(DateTimeOffset.UtcNow);

    protected ClientCredentialsTokenProtector TokenProtector { get; private set; } = default!;

    protected ConfiguredClientCredentialsService IssuedFor { get; } = new(ServiceName, Prefix, new Uri("https://portal.example.test/verify"));

    protected IBearerTokenValidator Validator { get; private set; } = default!;

    protected IBearerRouteForwarder Forwarder { get; private set; } = default!;

    protected RequestDelegate Next { get; private set; } = default!;

    protected BearerRouteMiddleware Middleware { get; private set; } = default!;

    protected static DefaultHttpContext Request(string path, params string[] authorization)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Get;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (authorization.Length > 0)
        {
            context.Request.Headers.Authorization = authorization;
        }

        return context;
    }

    protected static string Challenge(HttpContext context) => context.Response.Headers.WWWAuthenticate.ToString();

    protected string Issue(ConfiguredClientCredentialsService service) => TokenProtector.CreateToken(service, "orders-client");

    void Establish()
    {
        TokenProtector = new ClientCredentialsTokenProtector(DataProtection, Clock);
        var current = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                [ServiceName] = new()
                {
                    Backend = new() { BaseUrl = "https://portal.example.test" },
                    ClientCredentials = new() { RoutePrefix = Prefix, VerificationPath = "/verify" },
                    BearerRoutes =
                    [
                        new()
                        {
                            PathPrefix = Prefix,
                            Issuers = [new() { Issuer = "https://issuer.example.test" }],
                            Audiences = ["portal-api"],
                            ResourceMetadataUrl = ResourceMetadataUrl,
                        },
                    ],
                },
            },
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(current);

        Validator = Substitute.For<IBearerTokenValidator>();
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(callInfo => callInfo.Arg<HttpRequest>().Headers.Authorization.ToString() == $"Bearer {ValidExternalToken}"
                ? BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant", null)
                : BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "stub"));

        var accessPolicy = Substitute.For<IAccessPolicy>();
        accessPolicy.Evaluate(Arg.Any<ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>()).Returns(AccessDecision.Granted);
        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(Arg.Any<string>()).Returns(true);
        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver.ResolveEach(Arg.Any<HttpContext>()).Returns([]);

        Forwarder = Substitute.For<IBearerRouteForwarder>();
        Next = Substitute.For<RequestDelegate>();
        Middleware = new BearerRouteMiddleware(
            Next,
            options,
            Validator,
            Substitute.For<IBearerTokenIntrospector>(),
            accessPolicy,
            tenantVerifier,
            tenantResolver,
            Forwarder,
            TokenProtector,
            Substitute.For<ILogger<BearerRouteMiddleware>>());
    }
}
