// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend_for_publishing;

public class and_no_signing_key_is_given : given.an_auth_proxy_being_published
{
    Exception _exception;

    void Because() => _exception = Catch.Exception(() => _resource.WithSignedForwardingTo(_api));

    [Fact] void should_be_in_publish_mode() => _builder.ExecutionContext.IsPublishMode.ShouldBeTrue();
    [Fact] void should_require_a_provisioned_key() => _exception.ShouldBeOfExactType<ForwardedIdentitySigningKeyNotProvisioned>();
    [Fact] void should_not_generate_a_parameter() => _builder.Resources.OfType<ParameterResource>().ShouldBeEmpty();
    [Fact] async Task should_not_emit_signer_settings() => (await RawEnvironmentOf(_resource.Resource)).ShouldBeEmpty();
    [Fact] async Task should_not_emit_verifier_settings() => (await RawEnvironmentOf(_api.Resource)).ShouldBeEmpty();
}
