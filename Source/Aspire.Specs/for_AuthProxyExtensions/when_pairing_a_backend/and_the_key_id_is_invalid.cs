// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_the_key_id_is_invalid : given.an_auth_proxy_and_a_backend
{
    [Theory]
    [InlineData("")]
    [InlineData("key id")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public async Task should_refuse_the_key_id_without_declaring_configuration(string keyId)
    {
        Catch.Exception(() => _resource.WithSignedForwardingTo(_api, keyId: keyId)).ShouldBeOfExactType<InvalidForwardedIdentityKeyId>();
        _builder.Resources.OfType<ParameterResource>().ShouldBeEmpty();
        (await RawEnvironmentOf(_resource.Resource)).ShouldBeEmpty();
        (await RawEnvironmentOf(_api.Resource)).ShouldBeEmpty();
    }
}
