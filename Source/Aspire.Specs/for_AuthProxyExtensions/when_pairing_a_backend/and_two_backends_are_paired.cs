// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_two_backends_are_paired : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _environment;

    async Task Because()
    {
        var reports = _builder.AddContainer("reports", "example/reports");
        _resource.WithBackend("main", _api).WithBackend("reports", reports).WithSignedForwardingTo(_api).WithSignedForwardingTo(reports);
        _environment = await EnvironmentOf(_resource.Resource);
    }

    [Fact] void should_separate_keys_per_backend() => (_environment[$"{SignerPrefix}__SecretBase64"] != _environment["Cratis__AuthProxy__Services__reports__ForwardedIdentity__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_separate_audiences() => _environment["Cratis__AuthProxy__Services__reports__ForwardedIdentity__Audience"].ShouldEqual("reports");
    [Fact] void should_keep_the_first_audience() => _environment[$"{SignerPrefix}__Audience"].ShouldEqual("api");
}
