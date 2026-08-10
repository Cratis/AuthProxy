// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

/// <summary>
/// A trusted proxy nobody can parse stops the proxy rather than quietly leaving the ingress untrusted.
/// </summary>
/// <remarks>
/// Dropping the entry would leave a deployment that believes it declared a boundary running with a different
/// one, and every symptom of that — sign-ins recorded against the inner load balancer, geo headers discarded,
/// forwarded schemes refused — points somewhere other than the typo that caused it.
/// </remarks>
public class when_a_trusted_proxy_cannot_be_understood : an_ingress_configuration
{
    Exception? _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.Ingress.SectionKey}:TrustedProxies:0"] = "10.0.0.0/8",
        [$"{C.Ingress.SectionKey}:TrustedProxies:1"] = "ingress.example.com",
    };

    void Because() => _exception = Record.Exception(
        () => _serviceProvider.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_offending_value() => _exception!.Message.ShouldContain("ingress.example.com");
    [Fact] void should_name_the_configuration_key() => _exception!.Message.ShouldContain($"{C.Ingress.SectionKey}:TrustedProxies:1");
}
