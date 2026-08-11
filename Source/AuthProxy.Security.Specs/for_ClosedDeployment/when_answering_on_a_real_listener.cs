// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_ClosedDeployment;

/// <summary>
/// OWASP A05 — Security Misconfiguration. What a closed deployment writes onto the wire is one refusal, and
/// asserting that requires reading the wire.
/// </summary>
/// <remarks>
/// Every other spec about this mode runs on <c>WebApplicationFactory</c>'s in-memory test server, and an
/// exhaustive comparison taken there compares what the *application* wrote. Two things a caller receives are
/// invisible at that layer, and both of them were wrong:
/// <list type="bullet">
/// <item><description>
/// Kestrel adds its own <c>Server</c> header at serialization time, after every middleware has stopped
/// touching the response — so clearing the headers cannot remove it, and it was only switched off as a side
/// effect of configuring a management port. A deployment whose stated purpose is not to be discoverable was
/// answering every scanner with the name of what is running it.
/// </description></item>
/// <item><description>
/// The management middleware runs ahead of the admission gate, so a management path offered to the *public*
/// listener was refused by the management endpoints instead — a different status framing, a different body
/// and a <c>Cache-Control</c> nothing else carried. An unadmitted caller probing the documented default path
/// learned that an AuthProxy is here, that it has a management listener, and what its paths are called.
/// </description></item>
/// </list>
/// <para>
/// Compared as raw bytes rather than as parsed answers, because the parsed view is the one that hid this.
/// </para>
/// </remarks>
/// <param name="harness">The two running closed proxies and their shared origin.</param>
[Collection(ClosedDeploymentSpecCollection.Name)]
public class when_answering_on_a_real_listener(ClosedDeploymentHarness harness) : IAsyncLifetime
{
    const string UnknownPath = "/9f3c2a7b-a-path-that-was-never-there";

    readonly Dictionary<string, string> _answers = new(StringComparer.Ordinal);

    bool _originSawAnything;

    public async Task InitializeAsync()
    {
        harness.Origin.Clear();

        _answers["unknown"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithManagement, UnknownPath);
        _answers["root"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithManagement, "/");
        _answers["anonymous"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithManagement, ClosedDeploymentHarness.AnonymousPath);
        _answers["providers"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithManagement, WellKnownPaths.Providers);
        _answers["live"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithManagement, ClosedDeploymentHarness.LivePath);
        _answers["management-unknown"] = await ClosedDeploymentHarness.Raw(harness.ManagementPort, UnknownPath);

        _answers["bare-unknown"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithoutManagement, UnknownPath);
        _answers["bare-live"] = await ClosedDeploymentHarness.Raw(harness.PublicPortWithoutManagement, ClosedDeploymentHarness.LivePath);

        _originSawAnything = !harness.Origin.Received.IsEmpty;
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public void should_refuse_an_unknown_path() =>
        Assert.StartsWith("HTTP/1.1 404", _answers["unknown"], StringComparison.Ordinal);

    [Fact]
    public void should_never_name_the_server_that_is_answering() =>
        Assert.DoesNotContain(_answers.Values, answer => answer.Contains("Server:", StringComparison.OrdinalIgnoreCase));

    [Fact]
    public void should_answer_a_management_path_exactly_as_it_answers_a_path_that_was_never_there() =>
        Assert.Equal(_answers["unknown"], _answers["live"]);

    [Fact]
    public void should_answer_every_public_route_with_the_same_bytes() =>
        Assert.Single(new[] { _answers["unknown"], _answers["root"], _answers["anonymous"], _answers["providers"], _answers["live"] }.Distinct(StringComparer.Ordinal));

    [Fact]
    public void should_answer_the_same_whether_or_not_a_management_listener_was_opened() =>
        Assert.Equal(_answers["unknown"], _answers["bare-unknown"]);

    [Fact]
    public void should_answer_a_management_path_the_same_on_a_deployment_that_has_no_management_listener() =>
        Assert.Equal(_answers["unknown"], _answers["bare-live"]);

    [Fact]
    public void should_refuse_the_management_listener_itself_with_the_same_answer() =>
        Assert.Equal(_answers["unknown"], _answers["management-unknown"]);

    [Fact]
    public void should_let_nothing_at_all_reach_the_origin() =>
        Assert.False(_originSawAnything);
}
