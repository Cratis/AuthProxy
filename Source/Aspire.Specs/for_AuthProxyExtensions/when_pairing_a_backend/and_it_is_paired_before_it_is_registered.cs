// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_it_is_paired_before_it_is_registered : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _proxy;
    Dictionary<string, string> _backend;

    async Task Because()
    {
        _resource.WithSignedForwardingTo(_api).WithBackend("main", _api).WithSelectionTenantResolution(_api, "/tenants");
        _proxy = await EnvironmentOf(_resource.Resource);
        _backend = await EnvironmentOf(_api.Resource);
    }

    [Fact] void should_write_the_service_audience() => _proxy[$"{SignerPrefix}__Audience"].ShouldEqual("api");
    [Fact] void should_write_the_service_key_id() => _proxy[$"{SignerPrefix}__KeyId"].ShouldEqual("auth-proxy");
    [Fact] void should_share_the_verifier_secret() => (_proxy[$"{SignerPrefix}__SecretBase64"] == _backend[$"{VerifierPrefix}__Keys__0__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_also_pair_the_later_tenant_list() => (_proxy["Cratis__AuthProxy__TenantResolutions__0__Options__ForwardedIdentity__SecretBase64"] == _proxy[$"{SignerPrefix}__SecretBase64"]).ShouldBeTrue();
}
