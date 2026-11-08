// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SecurityMisconfiguration;

/// <summary>
/// A deployment with no trusted proxies starts and explains that forwarded headers are ignored,
/// naming the exact settings an operator can configure.
/// </summary>
/// <param name="harness">The running proxy, which declares no trusted proxies.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_no_trusted_proxies_are_declared(SecurityHarness harness) : IAsyncLifetime
{
    bool _namedTheConfigurationKey;
    bool _namedTheMode;
    bool _explainedIgnoredHeaders;

    public async ValueTask InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        await client.SendAsync(SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath));

        _explainedIgnoredHeaders = harness.Logs.Mentioning("ignoring forwarded headers", "connection");
        _namedTheConfigurationKey = harness.Logs.Mentioning($"{C.Ingress.SectionKey}:{nameof(C.Ingress.TrustedProxies)}");
        _namedTheMode = harness.Logs.Mentioning(
            $"{C.Ingress.SectionKey}:{nameof(C.Ingress.Mode)}",
            nameof(C.TrustedProxyMode.Configured));
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    [Fact] public void should_name_the_configuration_key_for_trusted_proxies() => Assert.True(_namedTheConfigurationKey);
    [Fact] public void should_name_the_mode_it_is_running_in() => Assert.True(_namedTheMode);
    [Fact] public void should_explain_ignored_headers_and_connection_values() => Assert.True(_explainedIgnoredHeaders);
}
