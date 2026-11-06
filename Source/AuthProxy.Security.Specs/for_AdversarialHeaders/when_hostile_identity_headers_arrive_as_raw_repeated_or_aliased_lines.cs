// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>Raw header lines are either refused or stripped before any origin observes them.</summary>
/// <param name="harness">The real-socket proxy.</param>
[Collection(ForwardingPathSpecCollection.Name)]
public class when_hostile_identity_headers_arrive_as_raw_repeated_or_aliased_lines(ForwardingPathHarness harness) : IAsyncLifetime
{
    static readonly Dictionary<string, (string Name, string Value)[]> _cases = new()
    {
        ["case-duplicates"] = [(Headers.PrincipalId, HostileIdentityHeaders.Marker), (Headers.PrincipalId.ToUpperInvariant(), HostileIdentityHeaders.Marker + "-second")],
        ["repeated-values"] = [(Headers.PrincipalId, HostileIdentityHeaders.Marker), (Headers.PrincipalId, HostileIdentityHeaders.Marker + "-second")],
        ["underscore-aliases"] = [("x_ms_client_principal_id", HostileIdentityHeaders.Marker), ("x_cratis_tenant_id", HostileIdentityHeaders.Marker), ("x_cratis_credential_kind", HostileIdentityHeaders.Marker)],
        ["optional-whitespace"] = [("x-cratis-credential-kind", " \t" + HostileIdentityHeaders.Marker + "\t ")],
        ["whitespace-before-colon"] = [(Headers.PrincipalId + " ", HostileIdentityHeaders.Marker)],
        ["obs-fold"] = [(Headers.PrincipalId, HostileIdentityHeaders.Marker + "\r\n " + HostileIdentityHeaders.Marker + "-continued")]
    };

    readonly Dictionary<string, (HttpStatusCode Status, string User, ForwardedRequest[] Requests)> _results = [];

    public async ValueTask InitializeAsync()
    {
        foreach (var (name, headers) in _cases)
        {
            harness.ClearOrigins();
            var user = SecurityHarness.UniqueUser("raw-header-stripping");
            var status = await harness.Raw(
                "GET",
                "/hostile",
                ForwardingPathHarness.PortalHost,
                authenticated: false,
                headers.Append((SecurityHarness.AuthenticatedUserHeader, user)).ToArray());
            Console.WriteLine($"Header wire case {name}: {(int)status}");
            _results[name] = (status, user, harness.Portal.Received.Concat(harness.Reports.Received).Concat(harness.ReportsFrontend.Received).Concat(harness.Admin.Received).ToArray());
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Theory]
    [InlineData("case-duplicates")]
    [InlineData("repeated-values")]
    [InlineData("underscore-aliases")]
    [InlineData("optional-whitespace")]
    public void should_forward_the_well_formed_request(string name) => Assert.Equal(HttpStatusCode.OK, _results[name].Status);

    [Theory]
    [InlineData("whitespace-before-colon")]
    [InlineData("obs-fold")]
    public void should_refuse_or_strip_malformed_lines(string name) => Assert.Contains(_results[name].Status, new[] { HttpStatusCode.BadRequest, HttpStatusCode.OK });

    [Theory]
    [InlineData("case-duplicates")]
    [InlineData("repeated-values")]
    [InlineData("underscore-aliases")]
    [InlineData("optional-whitespace")]
    [InlineData("whitespace-before-colon")]
    [InlineData("obs-fold")]
    public void should_not_forward_any_caller_supplied_identity_header(string name) => Assert.Empty(_results[name].Requests.SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData("case-duplicates")]
    [InlineData("repeated-values")]
    [InlineData("underscore-aliases")]
    [InlineData("optional-whitespace")]
    [InlineData("whitespace-before-colon")]
    [InlineData("obs-fold")]
    public void should_reach_no_origin_when_refused_or_forward_only_the_session_identity(string name) => Assert.Equal(
        _results[name].Status == HttpStatusCode.BadRequest ? [] : [_results[name].User],
        _results[name].Requests.Select(request => request.Value(Headers.PrincipalId)).ToArray());
}
