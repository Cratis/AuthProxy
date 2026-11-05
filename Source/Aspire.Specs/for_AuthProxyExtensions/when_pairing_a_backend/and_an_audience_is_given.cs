// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_an_audience_is_given : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _proxy;
    Dictionary<string, string> _backend;

    async Task Because()
    {
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api, audience: "custom-api", keyId: "custom-key");
        _proxy = await EnvironmentOf(_resource.Resource);
        _backend = await EnvironmentOf(_api.Resource);
    }

    [Fact] void should_use_the_given_signer_audience() => _proxy[$"{SignerPrefix}__Audience"].ShouldEqual("custom-api");
    [Fact] void should_use_the_given_verifier_audience() => _backend[$"{VerifierPrefix}__Audience"].ShouldEqual("custom-api");
    [Fact] void should_use_the_given_signer_key_id() => _proxy[$"{SignerPrefix}__KeyId"].ShouldEqual("custom-key");
    [Fact] void should_use_the_given_verifier_key_id() => _backend[$"{VerifierPrefix}__Keys__0__KeyId"].ShouldEqual("custom-key");
}
