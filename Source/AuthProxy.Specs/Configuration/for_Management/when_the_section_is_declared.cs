// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Configuration.for_Management;

/// <summary>
/// The keys a deployment writes are the surface that can silently be wrong, so they are asserted by name.
/// <para>
/// The Aspire package is a standalone NuGet package that cannot reference the proxy it configures, so the
/// only thing joining the two is the exact spelling of these environment variables. A rename on either side
/// binds nothing and falls back to a default: the listener would open on the default paths, or — for the
/// port, which has no default — not at all.
/// </para>
/// </summary>
public class when_the_section_is_declared : Specification
{
    C.AuthProxy _config;

    void Because() => _config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Management:BindAddress"] = "0.0.0.0",
            ["Management:Port"] = "9110",
            ["Management:LivePath"] = "/internal/alive",
            ["Management:ReadyPath"] = "/internal/serving"
        })
        .Build()
        .Get<C.AuthProxy>()!;

    [Fact] void should_bind_the_bind_address() => _config.Management!.BindAddress.ShouldEqual("0.0.0.0");
    [Fact] void should_bind_the_port() => _config.Management!.Port.ShouldEqual(9110);
    [Fact] void should_bind_the_liveness_path() => _config.Management!.LivePath.ShouldEqual("/internal/alive");
    [Fact] void should_bind_the_readiness_path() => _config.Management!.ReadyPath.ShouldEqual("/internal/serving");
}
