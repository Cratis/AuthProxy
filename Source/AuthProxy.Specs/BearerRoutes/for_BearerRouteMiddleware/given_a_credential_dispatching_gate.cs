// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes.PersonalAccessTokens;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

/// <summary>
/// A bearer-route gate whose collaborators record every call, so a spec can show which branch a credential reached.
/// </summary>
public abstract class given_a_credential_dispatching_gate : Specification
{
    protected const string PatOnlyPath = "/pat";
    protected const string OAuthPath = "/oauth";
    protected const string CombinedPath = "/both";
    protected const string JwtLikeToken = "eyJhbGciOiJSUzI1NiJ9.e30.c2ln";

    protected IBearerTokenValidator Validator { get; private set; } = default!;

    protected IBearerRouteForwarder Forwarder { get; private set; } = default!;

    protected RequestDelegate Next { get; private set; } = default!;

    protected BearerRouteMiddleware Middleware { get; private set; } = default!;

    protected ClientCredentialsTokenProtector TokenProtector { get; } = new(new EphemeralDataProtectionProvider());

    protected static DefaultHttpContext Request(string path, string method = "GET", params string[] authorization)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (authorization.Length > 0)
        {
            context.Request.Headers.Authorization = authorization;
        }

        return context;
    }

    protected static string Body(HttpContext context)
    {
        context.Response.BodyWriter.FlushAsync().AsTask().GetAwaiter().GetResult();
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body).ReadToEnd();
    }

    protected static string ErrorBody(string code) => $"{{\"error\":\"{code}\"}}";

    protected static string Challenge(HttpContext context) => context.Response.Headers.WWWAuthenticate.ToString();

    protected static string Pat(string resourceKey = "direct") => TestPersonalAccessTokens.Create(resourceKey);

    protected void Establish()
    {
        var current = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["api"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    BearerRoutes =
                    [
                        new()
                        {
                            PathPrefix = PatOnlyPath,
                            PersonalAccessTokens = new() { ResourceKey = "direct" },
                        },
                        new()
                        {
                            PathPrefix = OAuthPath,
                            Issuers = [new() { Issuer = "https://issuer.example.test" }],
                            Audiences = ["direct-api"],
                            ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/oauth",
                        },
                        new()
                        {
                            PathPrefix = CombinedPath,
                            Issuers = [new() { Issuer = "https://issuer.example.test" }],
                            Audiences = ["direct-api"],
                            PersonalAccessTokens = new() { ResourceKey = "direct" },
                            ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/both",
                        },
                    ],
                },
            },
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(current);
        Validator = Substitute.For<IBearerTokenValidator>();
        Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(BearerTokenValidation.Refused(BearerTokenValidationStatus.Invalid, "stub"));
        Forwarder = Substitute.For<IBearerRouteForwarder>();
        Next = Substitute.For<RequestDelegate>();
        Middleware = new BearerRouteMiddleware(
            Next,
            options,
            Validator,
            Substitute.For<IAccessPolicy>(),
            Substitute.For<ITenantVerifier>(),
            Substitute.For<ITenantResolver>(),
            Forwarder,
            TokenProtector,
            Substitute.For<ILogger<BearerRouteMiddleware>>());
    }
}
