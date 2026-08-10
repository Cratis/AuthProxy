// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_ManagementExtensions;

/// <summary>
/// The refusal actually reaches startup validation, rather than living in a validator nobody wired in.
/// <para>
/// A validator that is written but not registered passes every one of its own specs and refuses nothing,
/// which is the exact shape of the failure this feature is meant to prevent: a deployment that starts, and
/// then answers no probe on a port it never bound.
/// </para>
/// </summary>
public class when_the_declared_section_cannot_open_a_listener : given.a_deployment_serving_traffic
{
    ServiceProvider _services;
    Exception _error;

    protected override IDictionary<string, string?> ManagementSettings => new Dictionary<string, string?>
    {
        ["Cratis:AuthProxy:Management:BindAddress"] = "127.0.0.1"
    };

    void Establish()
    {
        _builder.AddIngressConfiguration();
        _builder.AddManagement();
        _services = Services();
    }

    void Because() => _error = Catch.Exception(() => _ = _services.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _error.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_port_key() => ((OptionsValidationException)_error).Failures.ShouldContain(_ => _.Contains("Cratis:AuthProxy:Management:Port", StringComparison.Ordinal));

    void Destroy() => _services.Dispose();
}
