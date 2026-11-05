// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningConfigurationValidator;

public class when_services_reuse_signing_material : given.a_signing_configuration
{
    [Theory]
    [InlineData("other-audience", "active-1")]
    [InlineData("spec-backend", "different-key-id")]
    [InlineData("other-audience", "different-key-id")]
    public void should_refuse_shared_material_and_name_only_the_two_paths(string audience, string keyId)
    {
        configuration.Services["other"] = new()
        {
            ForwardedIdentity = new() { Audience = audience, KeyId = keyId, SecretBase64 = settings.SecretBase64 }
        };
        Validate();
        result.Failed.ShouldBeTrue();
        result.Failures.Single().ShouldEqual($"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity");
    }

    [Theory]
    [InlineData("https://backend.test/app", "https://backend.test/app", true)]
    [InlineData("https://BACKEND.test:443/app", "https://backend.test/app", true)]
    [InlineData("https://backend.test", "https://backend.test/", true)]
    [InlineData("https://backend.test/app", "https://other.test/app", false)]
    [InlineData("https://backend.test/app", "http://backend.test/app", false)]
    [InlineData("https://backend.test/app", "https://backend.test:444/app", false)]
    [InlineData("https://backend.test/app", "https://backend.test/other", false)]
    [InlineData("https://backend.test/app", "https://backend.test/APP", false)]
    [InlineData("https://backend.test/app", "https://backend.test/app/", false)]
    [InlineData("https://backend.test/app/", "https://backend.test/app//", false)]
    [InlineData("", "", false)]
    [InlineData("https://backend.test/app", "", false)]
    [InlineData("", "https://backend.test/app", false)]
    [InlineData("relative", "relative", false)]
    [InlineData("ftp://backend.test/app", "ftp://backend.test/app", false)]
    [InlineData("https://backend.test/app?target=one", "https://backend.test/app?target=one", false)]
    [InlineData("https://backend.test/app#fragment", "https://backend.test/app#fragment", false)]
    public void should_share_material_only_for_an_unambiguous_backend_alias(string first, string second, bool allowed)
    {
        configuration.Services["main"].Backend = first.Length == 0 ? null : new() { BaseUrl = first };
        configuration.Services["other"] = new()
        {
            Backend = second.Length == 0 ? null : new() { BaseUrl = second },
            ForwardedIdentity = settings
        };
        Validate();
        result.Succeeded.ShouldEqual(allowed);
        if (!allowed)
        {
            result.Failures.Single().ShouldEqual($"{C.AuthProxy.SectionKey}:Services:main:ForwardedIdentity; {C.AuthProxy.SectionKey}:Services:other:ForwardedIdentity");
        }
    }

    [Fact]
    void should_not_infer_aliases_from_dns_discovered_replicas()
    {
        var backend = new C.ServiceEndpoint { BaseUrl = "https://backend.test/app", StickyRouting = new() { Enabled = true } };
        configuration.Services["main"].Backend = backend;
        configuration.Services["other"] = new() { Backend = backend, ForwardedIdentity = settings };
        Validate();
        result.Failed.ShouldBeTrue();
    }
}
