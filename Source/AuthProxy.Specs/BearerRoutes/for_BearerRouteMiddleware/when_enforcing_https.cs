// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Ingress;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_enforcing_https : given_a_credential_dispatching_gate
{
    void Establish() => Validator.Validate(Arg.Any<HttpRequest>(), Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>())
        .Returns(BearerTokenValidation.Success(new ClaimsPrincipal(new ClaimsIdentity("external")), "tenant-a"));

    [Theory]
    [InlineData(null)]
    [InlineData("Bearer opaque-token")]
    [InlineData("DPoP opaque-token")]
    public async Task should_refuse_http_before_reading_or_validating_credentials(string? credential)
    {
        var context = HttpRequest(credential: credential);

        // No credential header may be read on the refused path, including a malformed proof or cookie.
        var headers = context.Request.Headers;
        var unreadHeaders = Substitute.For<IHeaderDictionary>();
        context.Features.Get<IHttpRequestFeature>()!.Headers = unreadHeaders;

        await Middleware.InvokeAsync(context);

        Refused(context);
        unreadHeaders.ReceivedCalls().ShouldBeEmpty();
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
        Next.ReceivedCalls().ShouldBeEmpty();
        headers.Authorization.ToString().ShouldEqual(credential ?? string.Empty);
    }

    [Fact]
    public async Task should_accept_https() => await Accepted(Request(OAuthPath, "GET", "Bearer opaque-token"));

    [Fact]
    public async Task should_permit_explicit_local_development_http()
    {
        Current.Profile = C.DeploymentProfile.LocalDevelopment;
        await Accepted(HttpRequest());
    }

    [Theory]
    [InlineData("localhost", "127.0.0.1")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("[::1]", "::1")]
    public async Task should_permit_loopback_http(string host, string peer) => await Accepted(HttpRequest(host, peer));

    [Theory]
    [InlineData("localhost", "203.0.113.9")]
    [InlineData("127.0.0.1", "203.0.113.9")]
    [InlineData("[::1]", "203.0.113.9")]
    [InlineData("public.example.test", "127.0.0.1")]
    public async Task should_not_exempt_a_forged_loopback_host_or_a_public_host_on_a_loopback_ingress(string host, string peer)
    {
        var context = HttpRequest(host, peer);
        await Middleware.InvokeAsync(context);
        Refused(context);
        Validator.ReceivedCalls().ShouldBeEmpty();
        Forwarder.ReceivedCalls().ShouldBeEmpty();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task should_use_only_the_trusted_effective_scheme(bool trusted)
    {
        var context = HttpRequest();
        context.Request.Headers["X-Forwarded-Proto"] = "https";
        var policy = new TrustedProxyPolicy(Microsoft.Extensions.Options.Options.Create(new C.Ingress { TrustedProxies = trusted ? ["203.0.113.9"] : [] }));
        var options = new ForwardedHeadersOptions();
        policy.ApplyTo(options);
        var forwarded = new ForwardedHeadersMiddleware(Middleware.InvokeAsync, NullLoggerFactory.Instance, Microsoft.Extensions.Options.Options.Create(options));

        await forwarded.Invoke(context);

        if (trusted)
        {
            context.Request.Scheme.ShouldEqual("https");
            await Forwarder.Received(1).Forward(context, Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity>());
        }
        else
        {
            context.Request.Scheme.ShouldEqual("http");
            Refused(context);
            Validator.ReceivedCalls().ShouldBeEmpty();
            Forwarder.ReceivedCalls().ShouldBeEmpty();
        }
    }

    [Fact]
    public async Task should_leave_public_metadata_available_over_http()
    {
        var context = HttpRequest();
        context.Request.Path = BearerRouteTable.All(Current).Single(route => route.Prefix == OAuthPath).ResourceMetadataPath;
        await Middleware.InvokeAsync(context);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
        await Forwarder.Received(1).Forward(context, Arg.Any<ResolvedBearerRoute>(), null);
        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    [Fact]
    public async Task should_not_change_non_bearer_routes()
    {
        var context = HttpRequest();
        context.Request.Path = "/browser";
        await Middleware.InvokeAsync(context);
        await Next.Received(1).Invoke(context);
        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    DefaultHttpContext HttpRequest(string host = "public.example.test", string peer = "203.0.113.9", string? credential = "Bearer opaque-token")
    {
        var context = Request(OAuthPath, "GET", credential);
        context.Request.Scheme = "http";
        context.Request.Host = new HostString(host);
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        return context;
    }

    async Task Accepted(DefaultHttpContext context)
    {
        await Middleware.InvokeAsync(context);
        await Validator.Received(1).Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
        await Forwarder.Received(1).Forward(context, Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity>());
    }

    static void Refused(DefaultHttpContext context)
    {
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status400BadRequest);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        Challenge(context).ShouldBeEmpty();
        context.Response.Headers.Location.ToString().ShouldBeEmpty();
        Body(context).ShouldEqual(ErrorBody("invalid_request"));
    }
}
