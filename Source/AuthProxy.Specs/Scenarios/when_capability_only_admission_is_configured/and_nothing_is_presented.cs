// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Scenarios.when_capability_only_admission_is_configured;

/// <summary>
/// Every route this deployment has, crossed with every method a caller can reach it by, answers one
/// indistinguishable refusal.
/// <para>
/// This is the whole feature stated as one table. AuthProxy's interactive contract is otherwise an oracle
/// in five different voices: <c>/.cratis/login/{scheme}</c> says whether a provider is configured,
/// <c>/.cratis/providers</c> lists them, <c>/.cratis/token</c> confirms an AuthProxy is answering,
/// <c>SelectProviderMiddleware</c> answers a browser and an API caller differently, and the invite
/// middleware distinguishes an expired invitation from an invalid one. A closed deployment has to answer
/// all of them the same way it answers a path that was never there.
/// </para>
/// <para>
/// The two invitation routes are the pointed case: one carries a well-formed, signed-shaped token and the
/// other carries nonsense, and the caller must not be able to tell which was which. Nothing here ever looks
/// at the token, which is exactly why it cannot.
/// </para>
/// </summary>
/// <param name="factory">The closed proxy under test.</param>
public class and_nothing_is_presented(AuthProxyFactory factory) : IClassFixture<AuthProxyFactory>, IAsyncLifetime
{
    const string ValidShapedInvitation = "/invite/eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxMjMiLCJpc3MiOiJsb2JieSJ9.c2lnbmF0dXJl";
    const string InvalidInvitation = "/invite/not-a-token";

    static readonly string[] _routes =
    [
        "/",
        "/9f3c2a7b-a-path-that-was-never-there",
        "/private",
        AuthProxyFactory.AssetPath,
        AuthProxyFactory.PageAssetPath,
        WellKnownPaths.Providers,
        WellKnownPaths.Token,
        $"{WellKnownPaths.LoginPrefix}/github",
        WellKnownPaths.LoginPage,
        WellKnownPaths.Logout,
        "/signin-github",
        WellKnownPaths.Registration,
        ValidShapedInvitation,
        InvalidInvitation,
    ];

    static readonly HttpMethod[] _methods =
    [
        HttpMethod.Get,
        HttpMethod.Head,
        HttpMethod.Post,
        HttpMethod.Put,
        HttpMethod.Patch,
        HttpMethod.Delete,
        HttpMethod.Options,
        new("PROBE"),
    ];

    readonly List<ObservedAnswer> _answers = [];

    public async Task InitializeAsync()
    {
        using var client = factory.CreateProbingClient();

        foreach (var method in _methods)
        {
            foreach (var route in _routes)
            {
                _answers.Add(await ObservedAnswer.Capture(client, route, method));
            }
        }
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_answer_every_route_and_method_the_same_way_a_missing_path_is_answered() =>
        Assert.Empty(_answers.Where(answer => answer.StatusCode != 404).Select(answer => $"{answer.Method} {answer.Route} -> {answer.StatusCode}"));

    [Fact]
    public void should_answer_identically_for_every_route_asked_with_the_same_method() =>
        Assert.Empty(_answers
            .GroupBy(answer => answer.Method, StringComparer.Ordinal)
            .Where(group => group.Select(answer => answer.Shape).Distinct(StringComparer.Ordinal).Count() > 1)
            .Select(group => $"{group.Key} answers {group.Select(answer => answer.Shape).Distinct(StringComparer.Ordinal).Count()} different ways"));

    [Fact]
    public void should_answer_with_one_status_and_header_set_across_every_method() =>
        Assert.Single(_answers.Select(answer => answer.HeaderShape).Distinct(StringComparer.Ordinal));

    [Fact]
    public void should_answer_with_one_body_across_every_method_that_carries_one() =>
        Assert.Single(_answers
            .Where(answer => !string.Equals(answer.Method, "HEAD", StringComparison.Ordinal))
            .Select(answer => answer.Body)
            .Distinct(StringComparer.Ordinal));

    [Fact]
    public void should_answer_head_without_a_body() =>
        Assert.DoesNotContain(_answers, answer => string.Equals(answer.Method, "HEAD", StringComparison.Ordinal) && answer.Body.Length > 0);

    [Fact]
    public void should_never_name_the_methods_a_route_accepts() => ShouldCarryNothingNamed("Allow");

    [Fact]
    public void should_never_ask_the_caller_to_come_back_later() => ShouldCarryNothingNamed("Retry-After");

    [Fact]
    public void should_never_offer_a_way_to_authenticate() => ShouldCarryNothingNamed("WWW-Authenticate");

    [Fact]
    public void should_never_point_anywhere() => ShouldCarryNothingNamed("Location");

    [Fact]
    public void should_never_issue_a_cookie() => ShouldCarryNothingNamed("Set-Cookie");

    [Fact]
    public void should_not_tell_a_well_formed_invitation_from_nonsense() =>
        Assert.Equal(
            _answers.First(answer => string.Equals(answer.Route, ValidShapedInvitation, StringComparison.Ordinal)).Shape,
            _answers.First(answer => string.Equals(answer.Route, InvalidInvitation, StringComparison.Ordinal)).Shape);

    void ShouldCarryNothingNamed(string header) =>
        Assert.Empty(_answers.Where(answer => answer.Carries(header)).Select(answer => $"{answer.Method} {answer.Route}"));
}
