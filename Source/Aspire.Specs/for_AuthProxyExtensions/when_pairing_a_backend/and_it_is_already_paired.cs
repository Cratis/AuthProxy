// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_it_is_already_paired : given.an_auth_proxy_and_a_backend
{
    Exception _exception;

    void Establish() => _resource.WithSignedForwardingTo(_api);
    void Because() => _exception = Catch.Exception(() => _resource.WithSignedForwardingTo(_api));

    [Fact] void should_refuse_duplicate_pairing() => _exception.ShouldBeOfExactType<ForwardedIdentityAlreadyPaired>();
    [Fact] void should_not_generate_another_key() => _builder.Resources.OfType<ParameterResource>().Count().ShouldEqual(1);
}
