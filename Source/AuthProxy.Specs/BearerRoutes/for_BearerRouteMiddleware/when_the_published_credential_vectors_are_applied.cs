// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.Authorization;
using Cratis.AuthProxy.Vectors;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerRouteMiddleware;

public class when_the_published_credential_vectors_are_applied : given_a_published_vector_gate
{
    IReadOnlyDictionary<string, Func<JsonElement, PathString, Task>> Executions => new Dictionary<string, Func<JsonElement, PathString, Task>>(StringComparer.Ordinal)
    {
        ["pat-only-missing-credential"] = Missing,
        ["pat-only-no-oauth-discovery"] = NoDiscovery,
        ["pat-only-accepts-pat"] = Accepted,
        ["pat-only-rejects-oauth"] = WrongKind,
        ["oauth-only-missing-credential"] = Missing,
        ["oauth-only-accepts-oauth"] = Accepted,
        ["oauth-only-rejects-pat"] = WrongKind,
        ["combined-accepts-pat"] = Accepted,
        ["combined-accepts-oauth"] = Accepted,
        ["combined-missing-credential"] = Missing,
        ["combined-invalid-pat-no-fallback"] = InvalidPat,
        ["oauth-only-audience-mismatch"] = InvalidOAuth,
        ["combined-audience-mismatch-no-fallback"] = InvalidOAuth,
        ["oauth-only-scope-step-up"] = ScopeStepUp,
        ["combined-scope-step-up"] = ScopeStepUp,
        ["unbound-client-does-not-require-dpop"] = Accepted,
        ["oauth-scopes-do-not-grant-product-roles"] = PolicyDenied,
        ["mcp-errors-never-redirect"] = Missing,
        ["bound-token-requires-proof"] = (vector, path) => BoundToken(vector, path, "bound-token-requires-proof"),
        ["bound-token-requires-matching-key"] = (vector, path) => BoundToken(vector, path, "bound-token-requires-matching-key"),
        ["dpop-rejects-replayed-jti"] = (vector, path) => BoundToken(vector, path, "dpop-rejects-replayed-jti"),
        ["dpop-requires-matching-target"] = (vector, path) => BoundToken(vector, path, "dpop-requires-matching-target"),
        ["dpop-requires-matching-token-hash"] = (vector, path) => BoundToken(vector, path, "dpop-requires-matching-token-hash"),
        ["unknown-bearer-rejected-before-verification"] = UnsupportedScheme,
        ["dpop-requires-fresh-iat"] = (vector, path) => BoundToken(vector, path, "dpop-requires-fresh-iat"),
        ["dpop-requires-matching-method"] = (vector, path) => BoundToken(vector, path, "dpop-requires-matching-method"),
        ["cookie-plus-bearer-is-ambiguous"] = Cookie,
        ["multiple-credentials-rejected"] = Multiple,
        ["query-credential-rejected"] = Query,
    };

    [Fact]
    void should_account_for_every_manifest_id_exactly_once()
    {
        var ids = PublishedAuthorizationVectors.Manifest.GetProperty("cases").EnumerateArray().Select(_ => _.GetProperty("id").GetString()).ToArray();
        var accounted = Executions.Keys.Concat(PublishedVectorOwnership.NotApplicable.Keys).ToArray();
        accounted.Distinct(StringComparer.Ordinal).Count().ShouldEqual(accounted.Length);
        Assert.Equal(ids.Order(StringComparer.Ordinal), accounted.Order(StringComparer.Ordinal));
        Assert.All(PublishedVectorOwnership.NotApplicable.Values, reason => Assert.False(string.IsNullOrWhiteSpace(reason)));
    }

    [Theory]
    [MemberData(nameof(PublishedAuthorizationVectors.Cases), MemberType = typeof(PublishedAuthorizationVectors))]
    public async Task should_apply_the_published_case_or_identify_its_external_owner(string id)
    {
        var vector = PublishedAuthorizationVectors.Case(id);
        if (PublishedVectorOwnership.NotApplicable.TryGetValue(id, out var reason))
        {
            Assert.False(string.IsNullOrWhiteSpace(reason), $"Missing ownership explanation: {id}.");
            return;
        }

        Assert.True(Executions.TryGetValue(id, out var execute), $"Unmapped published case: {id}.");
        foreach (var profile in Profiles(vector))
        {
            Validator.ClearReceivedCalls();
            Forwarder.ClearReceivedCalls();
            Next.ClearReceivedCalls();
            await execute(vector, ProfilePath(profile));
        }
    }

    async Task Missing(JsonElement vector, PathString path)
    {
        var context = Request(path.Value);
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Body(context).ShouldEqual(ErrorBody("unauthorized"));
        if (vector.GetProperty("then").TryGetProperty("wwwAuthenticate", out var challenge))
        {
            Challenge(context).ShouldEqual(challenge.GetString().Replace("/mcp", path.Value, StringComparison.Ordinal));
        }

        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    async Task NoDiscovery(JsonElement vector, PathString path)
    {
        var context = Request("/.well-known/oauth-protected-resource" + path);
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    async Task Accepted(JsonElement vector, PathString path)
    {
        var pat = vector.GetProperty("then").TryGetProperty("branch", out var branch) && branch.GetString() == "pat";
        var context = Request(path.Value, "GET", $"Bearer {(pat ? Pat() : AccessToken(vector.GetProperty("given")))}");
        await Middleware.InvokeAsync(context);
        context.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
        _ = Forwarder.Received(1).Forward(context, Arg.Any<ResolvedBearerRoute>(), Arg.Any<BearerForwardedIdentity?>());
        Next.ReceivedCalls().ShouldBeEmpty();
        if (pat) Validator.ReceivedCalls().ShouldBeEmpty();
        else context.User.Identity.IsAuthenticated.ShouldBeTrue();
    }

    async Task WrongKind(JsonElement vector, PathString path)
    {
        var credential = path == PatOnlyPath ? AccessToken(vector.GetProperty("given")) : Pat();
        await RefuseBeforeValidation(vector, Request(path.Value, "GET", $"Bearer {credential}"));
    }

    Task InvalidPat(JsonElement vector, PathString path) => RefuseBeforeValidation(vector,
        Request(path.Value, "GET", $"Bearer {PersonalAccessTokens.TestPersonalAccessTokens.CreateWithBadChecksum("direct")}"));

    async Task RefuseBeforeValidation(JsonElement vector, HttpContext context)
    {
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Validator.ReceivedCalls().ShouldBeEmpty();
    }

    async Task InvalidOAuth(JsonElement vector, PathString path)
    {
        var context = Request(path.Value, "GET", $"Bearer {AccessToken(vector.GetProperty("given"))}");
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Challenge(context).ShouldContain("error=\"invalid_token\"");
        _ = Validator.Received(1).Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
    }

    async Task ScopeStepUp(JsonElement vector, PathString path)
    {
        Current.Services["api"].BearerRoutes.Single(_ => _.PathPrefix == path.Value).RequiredScopes =
            vector.GetProperty("when").GetProperty("requiredScopes").EnumerateArray().Select(_ => _.GetString()!).ToArray();
        var context = Request(path.Value, "GET", $"Bearer {AccessToken(vector.GetProperty("given"))}");
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Challenge(context).ShouldEqual(vector.GetProperty("then").GetProperty("wwwAuthenticate").GetString().Replace("/mcp", path.Value, StringComparison.Ordinal));
        Body(context).ShouldEqual(ErrorBody("insufficient_scope"));

        // Scope recommendations and retry limits are OAuth-client behavior, not additional gateway response fields.
    }

    async Task PolicyDenied(JsonElement vector, PathString path)
    {
        AccessPolicy.Evaluate(Arg.Any<ClaimsPrincipal>(), Arg.Any<C.AuthProxy>(), Arg.Any<string>(), Arg.Any<C.BearerRoute>())
            .Returns(AccessDecision.Denied("product-role"));
        var context = Request(path.Value, "GET", $"Bearer {AccessToken(vector.GetProperty("given"))}");
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Challenge(context).ShouldBeEmpty();
        _ = AccessPolicy.Received(1).Evaluate(Arg.Any<ClaimsPrincipal>(), Current, "api", Arg.Any<C.BearerRoute>());
    }

    async Task BoundToken(JsonElement vector, PathString path, string id)
    {
        using var proof = new PublishedDpopProof();
        var policy = Current.Services["api"].BearerRoutes.Single(route => route.PathPrefix == path.Value);
        policy.PersonalAccessTokens = null;
        policy.Dpop = new() { PublicOrigin = "https://direct.example.test" };
        var given = vector.GetProperty("given").EnumerateObject().ToDictionary(property => property.Name, property => (object)property.Value);
        given["cnf"] = new { jkt = id == "bound-token-requires-matching-key" ? new string('A', 43) : proof.Jkt };
        var token = AccessToken(JsonSerializer.SerializeToElement(given));
        var missing = id == "bound-token-requires-proof";
        var context = Request(path.Value, "GET", $"{(missing ? "Bearer" : "DPoP")} {token}");
        if (!missing) context.Request.Headers["DPoP"] = proof.Sign(token, path.Value!, id);
        if (id == "dpop-rejects-replayed-jti")
        {
            var first = Request(path.Value, "GET", $"DPoP {token}");
            first.Request.Headers["DPoP"] = context.Request.Headers["DPoP"];
            await Middleware.InvokeAsync(first);
            first.Response.StatusCode.ShouldEqual(StatusCodes.Status200OK);
            Forwarder.ClearReceivedCalls();
            Validator.ClearReceivedCalls();
        }
        await Middleware.InvokeAsync(context);
        AssertRefused(context, vector.GetProperty("then").GetProperty("status").GetInt32());
        Challenge(context).ShouldContain("DPoP");
        Challenge(context).ShouldContain("error=\"invalid_dpop_proof\"");
        Body(context).ShouldEqual(ErrorBody("invalid_dpop_proof"));
        _ = Validator.Received(1).Validate(context.Request, Arg.Any<ResolvedBearerRoute>(), Arg.Any<CancellationToken>());
    }

    Task UnsupportedScheme(JsonElement vector, PathString path) => RefuseBeforeValidation(vector,
        Request(path.Value, "GET", $"{vector.GetProperty("when").GetProperty("authorizationScheme").GetString()} {Pat()}"));

    async Task Cookie(JsonElement vector, PathString path)
    {
        var services = new ServiceCollection();
        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure(options => options.Cookie.Name = ".AuthProxy.Session");
        await using var provider = services.BuildServiceProvider();
        var context = Request(path.Value, "GET", $"Bearer {(path == PatOnlyPath ? Pat() : JwtLikeToken)}");
        context.RequestServices = provider;
        context.Request.Headers.Cookie = ".AuthProxy.Session=fixture";
        await RefuseBeforeValidation(vector, context);
        Challenge(context).ShouldEqual("Bearer error=\"invalid_request\"");
        Body(context).ShouldEqual(ErrorBody("invalid_request"));
    }

    Task Multiple(JsonElement vector, PathString path) => RefuseBeforeValidation(vector,
        Request(path.Value, "GET", $"Bearer {Pat()}", $"Bearer {JwtLikeToken}"));

    async Task Query(JsonElement vector, PathString path)
    {
        foreach (var header in new[] { false, true })
        {
            var context = Request(path.Value, "GET", header ? [$"Bearer {(path == PatOnlyPath ? Pat() : JwtLikeToken)}"] : []);
            context.Request.QueryString = new QueryString("?access_token=" + JwtLikeToken);
            await RefuseBeforeValidation(vector, context);
            Challenge(context).ShouldEqual("Bearer error=\"invalid_request\"");
            Body(context).ShouldEqual(ErrorBody("invalid_request"));
        }
    }
}
