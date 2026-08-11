// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Configuration.for_Management;

/// <summary>
/// Naming the port is all a deployment should have to do. Everything else defaults to the private,
/// conventional answer: loopback, and the two paths a Cratis deployment's probes are pointed at.
/// </summary>
public class when_only_the_port_is_declared : Specification
{
    C.AuthProxy _config;

    void Because() => _config = new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Management:Port"] = "9110" })
        .Build()
        .Get<C.AuthProxy>()!;

    [Fact] void should_keep_the_listener_on_loopback() => _config.Management!.BindAddress.ShouldEqual("127.0.0.1");
    [Fact] void should_default_the_liveness_path() => _config.Management!.LivePath.ShouldEqual("/health/live");
    [Fact] void should_default_the_readiness_path() => _config.Management!.ReadyPath.ShouldEqual("/health/ready");
}
