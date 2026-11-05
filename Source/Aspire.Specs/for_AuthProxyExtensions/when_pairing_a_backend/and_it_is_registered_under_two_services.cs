// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_it_is_registered_under_two_services : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, object> _proxy;
    Dictionary<string, object> _backend;

    async Task Because()
    {
        _resource.WithBackend("main", _api).WithBackend("alias", _api).WithSignedForwardingTo(_api);
        _proxy = await RawEnvironmentOf(_resource.Resource);
        _backend = await RawEnvironmentOf(_api.Resource);
    }

    [Fact] void should_share_the_audience() => _proxy["Cratis__AuthProxy__Services__alias__ForwardedIdentity__Audience"].ShouldEqual(_proxy[$"{SignerPrefix}__Audience"]);
    [Fact] void should_share_the_key_id() => _proxy["Cratis__AuthProxy__Services__alias__ForwardedIdentity__KeyId"].ShouldEqual(_proxy[$"{SignerPrefix}__KeyId"]);
    [Fact] void should_share_one_parameter() => ReferenceEquals(_proxy["Cratis__AuthProxy__Services__alias__ForwardedIdentity__SecretBase64"], _proxy[$"{SignerPrefix}__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_declare_only_one_verifier_key() => _backend.Keys.Count(key => key.EndsWith("__SecretBase64", StringComparison.Ordinal)).ShouldEqual(1);
    [Fact] void should_declare_only_one_secret_parameter() => _builder.Resources.OfType<ParameterResource>().Count().ShouldEqual(1);
}
