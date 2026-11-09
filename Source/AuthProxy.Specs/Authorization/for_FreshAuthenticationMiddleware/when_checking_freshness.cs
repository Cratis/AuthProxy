// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authorization.for_FreshAuthenticationMiddleware;

public class when_checking_freshness : Specification
{
    readonly DateTimeOffset _now = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    [Theory]
    [InlineData(0, true)]
    [InlineData(300, true)]
    [InlineData(301, false)]
    [InlineData(-1, false)]
    [InlineData(int.MaxValue, false)]
    public async Task should_gate_the_age_without_renewing_it(int age, bool passes)
    {
        var (context, middleware, next) = Create(age);
        await middleware.InvokeAsync(context);
        next.Called.ShouldEqual(passes);
        if (!passes) context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task should_refuse_an_oauth_session_uniformly_without_a_redirect()
    {
        var (context, middleware, next) = Create(int.MaxValue, "oauth");
        context.Request.Headers.Accept = "text/html";
        context.Request.Headers["Sec-Fetch-Dest"] = "document";
        await middleware.InvokeAsync(context);
        next.Called.ShouldBeFalse();
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
        context.Response.Headers.Location.Count.ShouldEqual(0);
        context.Response.Headers.WWWAuthenticate.Count.ShouldEqual(0);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        context.Response.Body.Length.ShouldEqual(0);
    }

    [Theory]
    [InlineData("GET", true, 302)]
    [InlineData("GET", false, 401)]
    [InlineData("POST", true, 401)]
    [InlineData("PUT", true, 401)]
    [InlineData("DELETE", false, 401)]
    public async Task should_only_redirect_safe_document_navigation(string method, bool document, int status)
    {
        var (context, middleware, next) = Create(301);
        context.Request.Method = method;
        context.Request.Headers.Accept = document ? "text/html" : "application/json";
        context.Request.Headers["Sec-Fetch-Dest"] = document ? "document" : "empty";
        await middleware.InvokeAsync(context);
        context.Response.StatusCode.ShouldEqual(status);
        next.Called.ShouldBeFalse();
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        if (status == 302)
        {
            context.Response.Headers.Location.ToString().ShouldContain("/login/oidc?");
            context.Response.Headers.Location.ToString().ShouldContain("fresh=1");
        }
        else
        {
            context.Response.Headers.WWWAuthenticate.ToString().ShouldEqual("Bearer error=\"insufficient_user_authentication\", max_age=\"300\"");
            context.Response.Headers.Location.Count.ShouldEqual(0);
            context.Response.Body.Length.ShouldEqual(0);
        }
    }

    [Theory]
    [InlineData("unconfigured")]
    [InlineData("unmatched")]
    [InlineData("anonymous")]
    [InlineData("internal")]
    public async Task should_preserve_unaffected_requests(string kind)
    {
        var (context, middleware, next) = Create(301, kind);
        await middleware.InvokeAsync(context);
        next.Called.ShouldBeTrue();
    }

    [Theory]
    [InlineData("bearer", "/main/approve", false)]
    [InlineData("bearer", "/main/read", true)]
    [InlineData("onbehalf", "/main/approve", false)]
    [InlineData("onbehalf", "/main/read", true)]
    [InlineData("", "/unrouted/x", false)]
    public async Task should_refuse_a_credential_that_cannot_prove_its_age_on_a_limited_path_only(string kind, string path, bool passes)
    {
        var (context, middleware, next) = Create(0, kind);
        context.Request.Path = path;
        await middleware.InvokeAsync(context);
        next.Called.ShouldEqual(passes);
        if (!passes) context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    }

    [Theory]
    [InlineData("X-HTTP-Method-Override", "DELETE")]
    [InlineData("x-http-method-override", "DELETE")]
    [InlineData("X-HTTP-Method", "DELETE")]
    [InlineData("X-Method-Override", "DELETE")]
    [InlineData("X-HTTP-Method-Override", "")]
    [InlineData("X-HTTP-Method-Override", "PATCH, DELETE")]
    public async Task should_refuse_method_override_on_a_post_to_the_delete_only_path(string header, string value)
    {
        var (context, middleware, next) = Create(301, methods: ["DELETE"]);
        context.Request.Method = "POST";
        context.Request.Headers[header] = value;
        await middleware.InvokeAsync(context);
        next.Called.ShouldBeFalse();
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
        context.Response.Headers.CacheControl.ToString().ShouldEqual("no-store");
        context.Response.Body.Length.ShouldEqual(0);
    }

    [Theory]
    [InlineData("GET", true)]
    [InlineData("HEAD", true)]
    [InlineData("OPTIONS", true)]
    [InlineData("TRACE", true)]
    [InlineData("POST", false)]
    [InlineData("PUT", false)]
    [InlineData("PATCH", false)]
    [InlineData("DELETE", false)]
    [InlineData("CONNECT", false)]
    [InlineData("CUSTOM", false)]
    public async Task should_union_non_safe_methods_without_affecting_safe_methods(string method, bool passes)
    {
        var (context, middleware, next) = Create(301, methods: ["DELETE"]);
        context.Request.Method = method;
        await middleware.InvokeAsync(context);
        next.Called.ShouldEqual(passes);
    }

    [Theory]
    [InlineData("unconfigured", "/main/approve")]
    [InlineData("", "/other/approve")]
    public async Task should_not_reject_overrides_for_a_service_without_freshness_rules(string kind, string path)
    {
        var (context, middleware, next) = Create(301, kind);
        context.Request.Path = path;
        context.Request.Headers["X-HTTP-Method-Override"] = "DELETE";
        await middleware.InvokeAsync(context);
        next.Called.ShouldBeTrue();
    }

    [Theory]
    [InlineData("/main/approve", "/main/approve", false)]
    [InlineData("/main/approve/", "/main/approve/", false)]
    [InlineData("/other/approve", "/other/approve", true)]
    public async Task should_use_the_selected_service_local_path(string path, string raw, bool passes)
    {
        var (context, middleware, next) = Create(301);
        context.Request.Path = path;
        context.Features.Get<IHttpRequestFeature>().RawTarget = raw;
        await middleware.InvokeAsync(context);
        next.Called.ShouldEqual(passes);
    }

    (DefaultHttpContext Context, FreshAuthenticationMiddleware Middleware, Invocation Next) Create(int age, string kind = "", string[]? methods = null)
    {
        var service = new C.Service { Backend = new() { BaseUrl = "http://main" }, PathPrefix = "/main", StripPathPrefix = true, FreshAuthentication = [new() { Path = "/approve", Methods = methods ?? [] }] };
        if (kind == "unconfigured") service.FreshAuthentication = null;
        if (kind == "anonymous") service.AnonymousPaths = ["/main/approve"];
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = service, ["other"] = new() { Backend = new() { BaseUrl = "http://other" }, PathPrefix = "/other", StripPathPrefix = true } } };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(config);
        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Path = kind == "unmatched" ? "/main/read" : kind == "internal" ? "/.cratis/providers" : "/main/approve";
        context.Response.Body = new MemoryStream();
        context.User = new ClaimsPrincipal(new ClaimsIdentity([], "session"));
        var properties = new AuthenticationProperties();
        SessionProvider.Stamp(context.User, properties, kind == "oauth" ? "github" : "oidc");
        if (kind == "oauth") config.Authentication.OAuthProviders = [new C.OAuthProvider { Name = "GitHub" }];
        if (age != int.MaxValue) SessionAuthenticationTime.Stamp(context.User, properties, _now.AddSeconds(-age));
        var authentication = Substitute.For<IAuthenticationService>();
        authentication.AuthenticateAsync(context, CookieAuthenticationDefaults.AuthenticationScheme).Returns(AuthenticateResult.Success(new AuthenticationTicket(context.User, properties, CookieAuthenticationDefaults.AuthenticationScheme)));
        context.RequestServices = new ServiceCollection().AddSingleton(authentication).BuildServiceProvider();
        if (kind == "bearer") context.Items[Authentication.AuthenticationServiceCollectionExtensions.SelectedSchemeItemKey] = "Bearer";
        if (kind == "onbehalf") context.Request.Headers.Cookie = $"{Cookies.OnBehalf}=x";
        var next = new Invocation();
        Task Pipeline(HttpContext _)
        {
            next.Called = true;
            return Task.CompletedTask;
        }

        return (context, new FreshAuthenticationMiddleware(Pipeline, monitor, new Clock(_now), Substitute.For<ILogger<FreshAuthenticationMiddleware>>()), next);
    }

    sealed class Invocation
    {
        public bool Called { get; set; }
    }

    sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
