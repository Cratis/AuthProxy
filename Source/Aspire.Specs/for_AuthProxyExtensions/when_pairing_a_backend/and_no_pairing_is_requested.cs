// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_no_pairing_is_requested : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, object> _proxy;
    Dictionary<string, object> _backend;

    async Task Because()
    {
        _resource.WithBackend("main", _api);
        _proxy = await RawEnvironmentOf(_resource.Resource);
        _backend = await RawEnvironmentOf(_api.Resource);
    }

    [Fact] void should_not_enable_signing_implicitly() => _proxy.Keys.Any(key => key.Contains("__ForwardedIdentity", StringComparison.Ordinal)).ShouldBeFalse();
    [Fact] void should_not_configure_a_verifier_implicitly() => _backend.ShouldBeEmpty();
    [Fact] void should_not_generate_a_key() => _builder.Resources.OfType<ParameterResource>().ShouldBeEmpty();
}
