// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SecurityMisconfiguration;

/// <summary>
/// OWASP A05 — Security Misconfiguration. A deployment that has not said where its ingress is keeps working
/// exactly as before and is told, by name, what to set.
/// <para>
/// Believing every caller's forwarded headers is the posture AuthProxy shipped with, so refusing to start
/// would break every existing deployment for a setting none of them has yet heard of. Keeping the behavior
/// and saying so is the step that costs a deployment nothing and gives it somewhere to go; the next major
/// release turns the same condition into a refusal.
/// </para>
/// <para>
/// The message has to carry the configuration key itself, not a description of it. An operator reading a
/// container log at the moment a deployment rolls has no interest in a discussion of forwarded headers — they
/// need the string to put in their manifest, and if it is not there the warning is just noise they will
/// filter out.
/// </para>
/// </summary>
/// <param name="harness">The running proxy, which declares no trusted proxies.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_no_trusted_proxies_are_declared(SecurityHarness harness) : IAsyncLifetime
{
    bool _namedTheConfigurationKey;
    bool _namedTheMode;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        await client.SendAsync(SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath));

        _namedTheConfigurationKey = harness.Logs.Mentioning($"{C.Ingress.SectionKey}:{nameof(C.Ingress.TrustedProxies)}");
        _namedTheMode = harness.Logs.Mentioning(
            $"{C.Ingress.SectionKey}:{nameof(C.Ingress.Mode)}",
            nameof(C.TrustedProxyMode.Configured));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_name_the_configuration_key_that_leaves_the_fallback() => Assert.True(_namedTheConfigurationKey);
    [Fact] public void should_name_the_mode_it_is_running_in() => Assert.True(_namedTheMode);
}
