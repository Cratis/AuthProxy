// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_a_binding_conflicts : Specification
{
    [Theory]
    [InlineData("tenant-a", "production", "tenant-a")]
    [InlineData("tenant-a", "staging", "tenant-b")]
    public async Task should_refuse_before_policy_verification_or_forwarding(string tenant, string environment, string target)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/mcp";
        context.Request.Headers.Authorization = "Bearer test-placeholder";
        var current = new C.AuthProxy
        {
            CredentialBinding = new() { Environment = "staging" },
            Services = new Dictionary<string, C.Service>
            {
                ["api"] = new()
                {
                    Backend = new() { BaseUrl = "https://backend.example.test" },
                    IdentityVerification = C.IdentityVerificationMode.BestEffort,
                    BearerRoutes = [new()
                    {
                        PathPrefix = "/mcp",
                        EnvironmentClaimType = "env",
                        Issuers = [new() { Issuer = "https://issuer.example.test" }],
                        Audiences = ["direct-api"],
                        ResourceMetadataUrl = "https://direct.example.test/.well-known/oauth-protected-resource/mcp",
                    }],
                },
            },
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(current);
        var validator = Substitute.For<IBearerTokenValidator>();
        validator.Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>()).Returns(BearerTokenValidation.Success(new(), tenant, environment));
        var resolver = Substitute.For<ITenantResolver>();
        resolver.ResolveEach(context).Returns([new(target, C.TenantSourceIdentifierResolverType.Host)]);
        var policy = Substitute.For<IAccessPolicy>();
        var verifier = Substitute.For<ITenantVerifier>();
        var forwarder = Substitute.For<IBearerRouteForwarder>();
        var next = Substitute.For<RequestDelegate>();
        var middleware = new BearerRouteMiddleware(next, options, validator, Substitute.For<IBearerTokenIntrospector>(), policy, verifier, resolver, forwarder, new(new EphemeralDataProtectionProvider()), Substitute.For<ILogger<BearerRouteMiddleware>>());
        await middleware.InvokeAsync(context);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        policy.ReceivedCalls().ShouldBeEmpty();
        verifier.ReceivedCalls().ShouldBeEmpty();
        forwarder.ReceivedCalls().ShouldBeEmpty();
        next.ReceivedCalls().ShouldBeEmpty();
        context.Items.ContainsKey(TenancyMiddleware.TenantIdItemKey).ShouldBeFalse();
    }
}
