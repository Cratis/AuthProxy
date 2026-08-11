// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_TrustedProxies;

/// <summary>
/// A deployment that has declared where its ingress sits is not nagged about it.
/// <para>
/// The counterpart to the warning a deployment without a boundary gets. Without this, that warning would be
/// satisfied by a message the proxy printed unconditionally, which would train every operator to ignore it —
/// and an alert that fires on correct configurations is worth less than no alert at all.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, which has declared its trusted proxies.</param>
[Collection(TrustedProxySpecCollection.Name)]
public class when_the_boundary_is_declared(TrustedProxyHarness harness) : IAsyncLifetime
{
    bool _warned;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        await client.SendAsync(TrustedProxyHarness.From(TrustedProxyHarness.TrustedPeer, TrustedProxyHarness.AnonymousPath));

        _warned = harness.Logs.Mentioning($"{C.Ingress.SectionKey}:{nameof(C.Ingress.TrustedProxies)}");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_not_warn_about_the_boundary() => Assert.False(_warned);
}
