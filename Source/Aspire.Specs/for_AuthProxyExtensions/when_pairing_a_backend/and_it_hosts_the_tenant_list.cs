// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_it_hosts_the_tenant_list : given.an_auth_proxy_and_a_backend
{
    const string TenantPrefix = "Cratis__AuthProxy__TenantResolutions__0__Options__ForwardedIdentity";
    Dictionary<string, string> _proxy;
    Dictionary<string, string> _backend;

    async Task Because()
    {
        _resource.WithBackend("main", _api).WithSelectionTenantResolution(_api, "/tenants").WithSignedForwardingTo(_api);
        _proxy = await EnvironmentOf(_resource.Resource);
        _backend = await EnvironmentOf(_api.Resource);
    }

    [Fact] void should_share_the_audience() => _proxy[$"{TenantPrefix}__Audience"].ShouldEqual(_proxy[$"{SignerPrefix}__Audience"]);
    [Fact] void should_share_the_key_id() => _proxy[$"{TenantPrefix}__KeyId"].ShouldEqual(_proxy[$"{SignerPrefix}__KeyId"]);
    [Fact] void should_share_the_secret() => (_proxy[$"{TenantPrefix}__SecretBase64"] == _proxy[$"{SignerPrefix}__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_declare_only_one_verifier_key() => _backend.Keys.Count(key => key.EndsWith("__SecretBase64", StringComparison.Ordinal)).ShouldEqual(1);
}
