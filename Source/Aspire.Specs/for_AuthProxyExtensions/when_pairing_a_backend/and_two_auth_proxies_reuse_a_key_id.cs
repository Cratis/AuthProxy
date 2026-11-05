// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_two_auth_proxies_reuse_a_key_id : given.an_auth_proxy_and_a_backend
{
    Exception _exception;

    void Establish() => _resource.WithSignedForwardingTo(_api);
    void Because() => _exception = Catch.Exception(() => _builder.AddContainer("edge-proxy", "cratis/authproxy").WithSignedForwardingTo(_api, keyId: "auth-proxy"));

    [Fact] void should_refuse_the_taken_key_id() => _exception.ShouldBeOfExactType<InvalidForwardedIdentityKeyId>();
    [Fact] void should_not_generate_another_key() => _builder.Resources.OfType<ParameterResource>().Count().ShouldEqual(1);
}
