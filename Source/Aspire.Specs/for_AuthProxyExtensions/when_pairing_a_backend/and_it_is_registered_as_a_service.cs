// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend;

public class and_it_is_registered_as_a_service : given.an_auth_proxy_and_a_backend
{
    Dictionary<string, string> _proxy;
    Dictionary<string, string> _backend;
    ParameterResource _parameter;

    async Task Because()
    {
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api);
        _proxy = await EnvironmentOf(_resource.Resource);
        _backend = await EnvironmentOf(_api.Resource);
        _parameter = _builder.Resources.OfType<ParameterResource>().Single();
    }

    [Fact] void should_use_the_backend_name_as_audience() => _proxy[$"{SignerPrefix}__Audience"].ShouldEqual("api");
    [Fact] void should_use_the_proxy_name_as_key_id() => _proxy[$"{SignerPrefix}__KeyId"].ShouldEqual("auth-proxy");
    [Fact] void should_generate_exactly_32_bytes() => Convert.FromBase64String(_proxy[$"{SignerPrefix}__SecretBase64"]).Length.ShouldEqual(32);
    [Fact] void should_enable_verified_trust() => _backend["Cratis__Arc__TrustForwardedIdentityHeaders"].ShouldEqual(bool.TrueString);
    [Fact] void should_enable_the_verifier() => _backend[$"{VerifierPrefix}__Enabled"].ShouldEqual(bool.TrueString);
    [Fact] void should_configure_the_backend_audience() => _backend[$"{VerifierPrefix}__Audience"].ShouldEqual("api");
    [Fact] void should_configure_the_backend_key_id() => _backend[$"{VerifierPrefix}__Keys__0__KeyId"].ShouldEqual("auth-proxy");
    [Fact] void should_share_the_secret_with_the_verifier() => (_backend[$"{VerifierPrefix}__Keys__0__SecretBase64"] == _proxy[$"{SignerPrefix}__SecretBase64"]).ShouldBeTrue();
    [Fact] void should_write_exactly_the_five_arc_settings() => _backend.Keys.Where(key => key.StartsWith("Cratis__Arc__", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ShouldEqual(new[] { "Cratis__Arc__TrustForwardedIdentityHeaders", $"{VerifierPrefix}__Enabled", $"{VerifierPrefix}__Audience", $"{VerifierPrefix}__Keys__0__KeyId", $"{VerifierPrefix}__Keys__0__SecretBase64" }.Order(StringComparer.Ordinal));
    [Fact] void should_name_the_parameter_for_the_pair() => _parameter.Name.ShouldEqual("auth-proxy-api-signing-key");
    [Fact] void should_mark_the_parameter_secret() => _parameter.Secret.ShouldBeTrue();
    [Fact] void should_have_no_persisted_default() => _parameter.Default.ShouldBeNull();
}
