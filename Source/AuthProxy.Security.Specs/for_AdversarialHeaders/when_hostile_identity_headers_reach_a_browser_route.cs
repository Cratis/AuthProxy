// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>
/// Browser and anonymous routes strip caller-supplied identity headers.
/// </summary>
/// <param name="harness">The running proxy.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_hostile_identity_headers_reach_a_browser_route(SecurityHarness harness) : IAsyncLifetime
{
    readonly Dictionary<(HostileHeaderVariant, bool), (HttpStatusCode Status, string User, ForwardedRequest[] Requests)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            foreach (var authenticated in new[] { true, false })
            {
                harness.Origin.Clear();
                var user = SecurityHarness.UniqueUser("header-stripping");
                using var request = authenticated
                    ? SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath, user)
                    : SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath);
                HostileIdentityHeaders.ApplyTo(request, variant);
                using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
                _results[(variant, authenticated)] = (response.StatusCode, user, harness.Origin.Received.ToArray());
            }
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Theory]
    [InlineData(HostileHeaderVariant.Exact, true)]
    [InlineData(HostileHeaderVariant.Upper, true)]
    [InlineData(HostileHeaderVariant.Mixed, true)]
    [InlineData(HostileHeaderVariant.Duplicated, true)]
    [InlineData(HostileHeaderVariant.CaseDuplicated, true)]
    [InlineData(HostileHeaderVariant.Underscored, true)]
    [InlineData(HostileHeaderVariant.Exact, false)]
    [InlineData(HostileHeaderVariant.Upper, false)]
    [InlineData(HostileHeaderVariant.Mixed, false)]
    [InlineData(HostileHeaderVariant.Duplicated, false)]
    [InlineData(HostileHeaderVariant.CaseDuplicated, false)]
    [InlineData(HostileHeaderVariant.Underscored, false)]
    public void should_forward_the_request(HostileHeaderVariant variant, bool authenticated) => Assert.Equal(HttpStatusCode.OK, _results[(variant, authenticated)].Status);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact, true)]
    [InlineData(HostileHeaderVariant.Upper, true)]
    [InlineData(HostileHeaderVariant.Mixed, true)]
    [InlineData(HostileHeaderVariant.Duplicated, true)]
    [InlineData(HostileHeaderVariant.CaseDuplicated, true)]
    [InlineData(HostileHeaderVariant.Underscored, true)]
    [InlineData(HostileHeaderVariant.Exact, false)]
    [InlineData(HostileHeaderVariant.Upper, false)]
    [InlineData(HostileHeaderVariant.Mixed, false)]
    [InlineData(HostileHeaderVariant.Duplicated, false)]
    [InlineData(HostileHeaderVariant.CaseDuplicated, false)]
    [InlineData(HostileHeaderVariant.Underscored, false)]
    public void should_not_forward_any_caller_supplied_identity_header(HostileHeaderVariant variant, bool authenticated) => Assert.Empty(_results[(variant, authenticated)].Requests.SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_only_the_sessions_identity(HostileHeaderVariant variant) => Assert.Equal(_results[(variant, true)].User, _results[(variant, true)].Requests.Last(request => request.Path == SecurityHarness.ProtectedPath).Value(Headers.PrincipalId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_only_the_resolved_tenant(HostileHeaderVariant variant) => Assert.Equal(SecurityHarness.TenantId, _results[(variant, true)].Requests.Last(request => request.Path == SecurityHarness.ProtectedPath).Value(Headers.TenantId));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_not_invent_an_anonymous_principal(HostileHeaderVariant variant) => Assert.DoesNotContain(Assert.Single(_results[(variant, false)].Requests).Headers.Keys, name => name.StartsWith(Headers.PrincipalPrefix, StringComparison.OrdinalIgnoreCase));
}
