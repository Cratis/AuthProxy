// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_another_app_host_run_pairs_it : given.an_auth_proxy_and_a_backend
{
    bool _different;

    async Task Because()
    {
        var other = DistributedApplication.CreateBuilder();
        var api = other.AddContainer("api", "example/api");
        var proxy = other.AddContainer("auth-proxy", "cratis/authproxy");
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api);
        proxy.WithBackend("main", api).WithSignedForwardingTo(api);
        _different = (await EnvironmentOf(_resource.Resource))[$"{SignerPrefix}__SecretBase64"] != (await EnvironmentOf(proxy.Resource))[$"{SignerPrefix}__SecretBase64"];
    }

    [Fact] void should_generate_a_new_key_per_run() => _different.ShouldBeTrue();
}
