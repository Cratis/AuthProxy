// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_two_auth_proxies_pair_it : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _backend;

    async Task Because()
    {
        _resource.WithSignedForwardingTo(_api);
        _builder.AddContainer("edge-proxy", "cratis/authproxy").WithSignedForwardingTo(_api);
        _backend = await EnvironmentOf(_api.Resource);
    }

    [Fact] void should_keep_the_first_key_id() => _backend[$"{VerifierPrefix}__Keys__0__KeyId"].ShouldEqual("auth-proxy");
    [Fact] void should_append_the_second_key_id() => _backend[$"{VerifierPrefix}__Keys__1__KeyId"].ShouldEqual("edge-proxy");
    [Fact] void should_use_independent_keys() => (_backend[$"{VerifierPrefix}__Keys__0__SecretBase64"] != _backend[$"{VerifierPrefix}__Keys__1__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_keep_one_audience() => _backend[$"{VerifierPrefix}__Audience"].ShouldEqual("api");
}
