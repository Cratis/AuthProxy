// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Concurrent;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.BearerRoutes.Dpop;
using Cratis.AuthProxy.BearerRoutes.Introspection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class given_a_dpop_gate : given_a_signed_proof
{
    protected C.AuthProxy Options;
    protected C.BearerRoute Policy;
    protected ResolvedBearerRoute Route;
    protected SharedReplayStore Store;
    protected IBearerRouteForwarder Forwarder;
    protected RequestDelegate Next;
    protected BearerRouteMiddleware Gate;
    protected BearerTokenValidation Validation;
    protected EphemeralDataProtectionProvider Protection;
    protected FixedClock Clock;

    void Establish()
    {
        Policy = new()
        {
            PathPrefix = "/oauth",
            Issuers = [new() { Issuer = "https://issuer.example.test" }],
            Audiences = ["direct-api"],
            ResourceMetadataUrl = "https://api.example.test/.well-known/oauth-protected-resource",
            Dpop = new() { PublicOrigin = "https://api.example.test", PublicPathPrefix = "/mcp" },
        };
        Options = new() { Services = new Dictionary<string, C.Service> { ["api"] = new() { Backend = new() { BaseUrl = "https://backend.example.test" }, BearerRoutes = [Policy] } } };
        BearerRouteTable.TryMatch(new PathString("/oauth"), Options, out Route).ShouldBeTrue();
        Validation = BearerTokenValidator.ValidateClaims(Route, Route.Issuers[0], [new("sub", "synthetic-subject"), new("tid", "tenant-a"), new("cnf", "{\"jkt\":\"" + Jkt + "\"}")]);
        Validation.Succeeded.ShouldBeTrue();
        Forwarder = Substitute.For<IBearerRouteForwarder>();
        Next = Substitute.For<RequestDelegate>();
        Protection = new();
        Store = new();
        Clock = new();
        Gate = Replica();
    }

    protected BearerRouteMiddleware Replica()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(Options);
        var validator = Substitute.For<IBearerTokenValidator>();
        validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
            .Returns(call => DpopPresentation.Check(call.Arg<HttpRequest>(), Route, Validation));
        var access = Substitute.For<IAccessPolicy>();
        access.Evaluate(Arg.Any<ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>()).Returns(AccessDecision.Granted);
        var tenants = Substitute.For<ITenantVerifier>();
        tenants.VerifyAsync(Arg.Any<string>()).Returns(true);
        return new(Next, options, validator, Substitute.For<IBearerTokenIntrospector>(), access, tenants, Substitute.For<ITenantResolver>(), Forwarder, new ClientCredentialsTokenProtector(Protection), Substitute.For<ILogger<BearerRouteMiddleware>>(), new DpopEnforcement(Store, Protection, Clock, Substitute.For<ILogger<DpopEnforcement>>(), Microsoft.Extensions.Options.Options.Create(Options)));
    }

    protected DefaultHttpContext Request(string? proof = null, string scheme = "DPoP")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/oauth";
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = "/oauth?not-signed=true";
        context.Request.Headers.Authorization = scheme + " " + Token;
        context.Request.Headers["DPoP"] = proof ?? Proof();
        context.Response.Body = new MemoryStream();
        return context;
    }

    protected void Refused(HttpContext context, int status, string? error = "invalid_dpop_proof")
    {
        context.Response.StatusCode.ShouldEqual(status);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        context.Response.Headers.Location.ToString().ShouldBeEmpty();
        if (error is not null) context.Response.Headers.WWWAuthenticate.ToString().ShouldContain(error);
        context.User.Identity?.IsAuthenticated.ShouldNotEqual(true);
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
    }

    protected sealed class FixedClock : TimeProvider
    {
        public long Seconds { get; set; } = Now;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(Seconds);
    }

    protected sealed class SharedReplayStore : IDpopReplayStore
    {
        readonly ConcurrentDictionary<string, bool> _seen = new();
        public bool Available { get; set; } = true;
        public long ClockOffset { get; set; }
        public int Count => _seen.Count;
        public Task<DpopReplayResult> CheckHealth(CancellationToken cancellationToken) => Task.FromResult(Available && Math.Abs(ClockOffset) <= 30 ? DpopReplayResult.Accepted : DpopReplayResult.Unavailable);
        public async Task<DpopReplayResult> TryConsume(string origin, string jkt, string jti, CancellationToken cancellationToken) =>
            await CheckHealth(cancellationToken) != DpopReplayResult.Accepted ? DpopReplayResult.Unavailable : _seen.TryAdd(origin + "\n" + jkt + "\n" + jti, true) ? DpopReplayResult.Accepted : DpopReplayResult.Replay;
    }
}
