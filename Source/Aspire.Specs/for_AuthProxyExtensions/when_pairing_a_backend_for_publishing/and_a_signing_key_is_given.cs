// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Aspire.Hosting.Publishing;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_pairing_a_backend_for_publishing;

public class and_a_signing_key_is_given : given.an_auth_proxy_being_published
{
    ParameterResource _key;
    Dictionary<string, object> _proxy;
    Dictionary<string, object> _backend;
    JsonElement _manifest;

    async Task Because()
    {
        var key = _builder.AddParameter("api-key", secret: true);
        _key = key.Resource;
        _resource.WithBackend("main", _api).WithSignedForwardingTo(_api, signingKey: key);
        _proxy = await RawEnvironmentOf(_resource.Resource);
        _backend = await RawEnvironmentOf(_api.Resource);
        await using var stream = new MemoryStream();
        await using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            var context = new ManifestPublishingContext(_builder.ExecutionContext, ".", writer, default);
            await context.WriteEnvironmentVariablesAsync(_api.Resource);
            writer.WriteStartObject("proxy");
            await context.WriteEnvironmentVariablesAsync(_resource.Resource);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        using var document = JsonDocument.Parse(stream.ToArray());
        _manifest = document.RootElement.Clone();
    }

    [Fact] void should_use_the_supplied_signer_parameter() => ReferenceEquals(_proxy[$"{SignerPrefix}__SecretBase64"], _key).ShouldBeTrue();
    [Fact] void should_use_the_supplied_verifier_parameter() => ReferenceEquals(_backend[$"{VerifierPrefix}__Keys__0__SecretBase64"], _key).ShouldBeTrue();
    [Fact] void should_accept_the_secret_parameter() => _key.Secret.ShouldBeTrue();
    [Fact] void should_emit_a_parameter_expression() => _key.ValueExpression.ShouldEqual("{api-key.value}");
    [Fact] void should_not_generate_another_parameter() => _builder.Resources.OfType<ParameterResource>().Single().ShouldEqual(_key);
    [Fact] void should_not_emit_literal_key_material() => _proxy.Values.Concat(_backend.Values).OfType<string>().Any(IsKeyMaterial).ShouldBeFalse();
    [Fact] void should_publish_only_a_reference_for_the_key() => _manifest.GetProperty("env").GetProperty($"{VerifierPrefix}__Keys__0__SecretBase64").GetString().ShouldEqual("{api-key.value}");
    [Fact] void should_publish_only_a_reference_for_the_signer_key() => _manifest.GetProperty("proxy").GetProperty("env").GetProperty($"{SignerPrefix}__SecretBase64").GetString().ShouldEqual("{api-key.value}");
    [Fact] void should_not_put_key_material_in_the_manifest() => _manifest.GetProperty("env").EnumerateObject().Concat(_manifest.GetProperty("proxy").GetProperty("env").EnumerateObject()).Any(property => IsKeyMaterial(property.Value.GetString()!)).ShouldBeFalse();

    static bool IsKeyMaterial(string value) => Convert.TryFromBase64String(value, new byte[32], out var count) && count == 32;
}
