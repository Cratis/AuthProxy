// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_a_signing_key_is_given : given.an_auth_proxy_and_a_backend
{
    ParameterResource _key;
    Dictionary<string, object> _proxy;
    Dictionary<string, object> _backend;

    async Task Because()
    {
        var key = _builder.AddParameter("api-key", secret: true);
        _key = key.Resource;
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api, signingKey: key);
        _proxy = await RawEnvironmentOf(_resource.Resource);
        _backend = await RawEnvironmentOf(_api.Resource);
    }

    [Fact] void should_accept_the_secret_parameter() => _key.Secret.ShouldBeTrue();
    [Fact] void should_use_the_supplied_signer_parameter() => ReferenceEquals(_proxy[$"{SignerPrefix}__SecretBase64"], _key).ShouldBeTrue();
    [Fact] void should_use_the_supplied_verifier_parameter() => ReferenceEquals(_backend[$"{VerifierPrefix}__Keys__0__SecretBase64"], _key).ShouldBeTrue();
    [Fact] void should_not_generate_another_parameter() => _builder.Resources.OfType<ParameterResource>().Single().ShouldEqual(_key);
}
