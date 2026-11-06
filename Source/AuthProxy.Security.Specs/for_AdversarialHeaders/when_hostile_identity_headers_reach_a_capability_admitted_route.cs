// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AdversarialHeaders;

/// <summary>Admitted requests forward only the session's identity.</summary>
/// <param name="harness">The running capability-admitted proxy.</param>
[Collection(CapabilityOnlySpecCollection.Name)]
public class when_hostile_identity_headers_reach_a_capability_admitted_route(CapabilityOnlyHarness harness) : IAsyncLifetime
{
    readonly Dictionary<HostileHeaderVariant, (HttpStatusCode Status, string User, ForwardedRequest[] Requests)> _results = [];

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        foreach (var variant in HostileIdentityHeaders.Variants)
        {
            harness.Origin.Clear();
            var transaction = await CapabilityOnlyHarness.Admit(client);
            var user = SecurityHarness.UniqueUser("header-admission");
            using var request = SecurityHarness.Authenticated(HttpMethod.Get, CapabilityOnlyHarness.ProtectedPath, user);
            request.Headers.TryAddWithoutValidation("Cookie", $"{Cookies.EntryTransaction}={transaction}");
            HostileIdentityHeaders.ApplyTo(request, variant);
            using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
            _results[variant] = (response.StatusCode, user, harness.Origin.Received.ToArray());
        }
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_request(HostileHeaderVariant variant) => Assert.Equal(HttpStatusCode.OK, _results[variant].Status);

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_not_forward_any_caller_supplied_identity_header(HostileHeaderVariant variant) => Assert.Empty(_results[variant].Requests.SelectMany(request => HostileIdentityHeaders.Leaks(request.Headers)));

    [Theory]
    [InlineData(HostileHeaderVariant.Exact)]
    [InlineData(HostileHeaderVariant.Upper)]
    [InlineData(HostileHeaderVariant.Mixed)]
    [InlineData(HostileHeaderVariant.Duplicated)]
    [InlineData(HostileHeaderVariant.CaseDuplicated)]
    [InlineData(HostileHeaderVariant.Underscored)]
    public void should_forward_the_admitted_sessions_identity(HostileHeaderVariant variant) => Assert.Equal(_results[variant].User, _results[variant].Requests.Last(request => request.Path == CapabilityOnlyHarness.ProtectedPath).Value(Headers.PrincipalId));
}
