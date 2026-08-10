// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_ManagementExtensions;

/// <summary>
/// The management listener is <em>added to</em> the addresses the host already had, never substituted for
/// them.
/// <para>
/// This is the one assertion standing between an opt-in health endpoint and a total outage. Declaring the
/// listener the idiomatic-looking way — <c>ConfigureKestrel(options =&gt; options.Listen(...))</c> — makes
/// Kestrel discard the hosting addresses entirely, because <c>PreferHostingUrls</c> is
/// <see langword="false"/> by default: it logs "Overriding address(es)" and binds only what <c>Listen</c>
/// named. The public listener
/// of every containerized deployment comes from those hosting addresses, so switching on a health endpoint
/// would take the proxy off the network and leave a perfectly healthy-looking probe answering on loopback.
/// </para>
/// </summary>
public class when_a_management_section_is_declared : given.a_deployment_serving_traffic
{
    ServiceProvider _services;

    protected override IDictionary<string, string?> ManagementSettings => new Dictionary<string, string?>
    {
        ["Cratis:AuthProxy:Management:Port"] = "9110"
    };

    void Because()
    {
        _builder.AddManagement();
        _services = Services();
    }

    [Fact] void should_keep_the_public_listener() => DeclaredAddresses.ShouldContain(PublicUrl);
    [Fact] void should_add_the_management_listener() => DeclaredAddresses.ShouldContain("http://127.0.0.1:9110");
    [Fact] void should_declare_exactly_two_listeners() => DeclaredAddresses.Count.ShouldEqual(2);
    [Fact] void should_register_the_readiness_check() => _builder.Services.ShouldContain(_ => _.ServiceType == typeof(IReadinessCheck) && _.ImplementationType == typeof(DataProtectionReadiness));

    void Destroy() => _services.Dispose();
}
