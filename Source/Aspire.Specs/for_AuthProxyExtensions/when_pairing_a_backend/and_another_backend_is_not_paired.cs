// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_another_backend_is_not_paired : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _proxy;
    Dictionary<string, string> _other;

    async Task Because()
    {
        var other = _builder.AddContainer("other", "example/other");
        _resource.WithBackend("main", _api).WithBackend("other", other).WithSignedForwardingTo(_api);
        _proxy = await EnvironmentOf(_resource.Resource);
        _other = await EnvironmentOf(other.Resource);
    }

    [Fact] void should_not_sign_the_other_service() => _proxy.Keys.Any(key => key.StartsWith("Cratis__AuthProxy__Services__other__ForwardedIdentity", StringComparison.Ordinal)).ShouldBeFalse();
    [Fact] void should_not_configure_the_other_verifier() => _other.Keys.Any(key => key.StartsWith("Cratis__Arc__", StringComparison.Ordinal)).ShouldBeFalse();
}
