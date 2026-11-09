// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_configuring_a_custom_tenant_header : Specification
{
    [Fact]
    public void should_strip_the_configured_header_and_its_underscore_alias_inbound()
    {
        var config = new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["app"] = new() { ForwardedIdentity = new() { Version = "v2", TenantHeader = "x-workforce-tenant" } } } };
        var headers = new HeaderDictionary { ["X-Workforce-Tenant"] = "spoofed", ["x_workforce_tenant"] = "spoofed-alias", ["x-unrelated"] = "retained" };
        ForwardedIdentityTenantHeader.Strip(headers, config);
        Assert.Single(headers);
        Assert.Equal("retained", headers["x-unrelated"].ToString());
    }

    [Theory]
    [InlineData("Authorization")]
    [InlineData("DPoP")]
    [InlineData("Host")]
    [InlineData("x-ms-client-principal-id")]
    [InlineData("x_ms_client_principal")]
    [InlineData("x-cratis-issuer")]
    [InlineData("x-cratis-forwarded-identity-signature")]
    [InlineData("x-cratis-microservice")]
    [InlineData("invalid header")]
    [InlineData("")]
    public void should_refuse_reserved_or_invalid_tenant_headers_at_configuration_validation(string name)
    {
        var settings = when_signing_with_explicit_trusted_context.Settings();
        settings.TenantHeader = name;
        Assert.False(ForwardedIdentityV2SigningKey.IsValidSettings(settings));
    }

    [Fact]
    public void should_reserve_every_authproxy_header_except_the_canonical_tenant_header()
    {
        var names = typeof(Headers).GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .Where(name => name != Headers.TenantId);
        foreach (var name in names)
        {
            Assert.False(ForwardedIdentityTenantHeader.IsValid(name));
            Assert.False(ForwardedIdentityTenantHeader.IsValid(name.ToUpperInvariant().Replace('-', '_')));
        }
        Assert.True(ForwardedIdentityTenantHeader.IsValid(Headers.TenantId));
    }

    [Theory]
    [InlineData("Connection")]
    [InlineData("Keep-Alive")]
    [InlineData("Proxy-Connection")]
    [InlineData("Proxy-Authenticate")]
    [InlineData("Proxy-Authorization")]
    [InlineData("TE")]
    [InlineData("Trailer")]
    [InlineData("Transfer-Encoding")]
    [InlineData("Upgrade")]
    [InlineData("Expect")]
    [InlineData("Forwarded")]
    [InlineData("X-Forwarded-For")]
    [InlineData("X-Forwarded-Host")]
    [InlineData("X-Forwarded-Proto")]
    [InlineData("X-Forwarded-Custom")]
    [InlineData("Content-Length")]
    [InlineData("Content-Type")]
    [InlineData("Content-Encoding")]
    [InlineData("Content-Custom")]
    public void should_reserve_transport_forwarding_and_content_headers_and_their_aliases(string name)
    {
        Assert.False(ForwardedIdentityTenantHeader.IsValid(name));
        Assert.False(ForwardedIdentityTenantHeader.IsValid(name.ToLowerInvariant().Replace('-', '_')));
    }

    [Fact]
    public void should_not_retain_a_caller_tenant_when_the_gateway_has_no_resolved_tenant()
    {
        using var fixture = new BrowserSessionFixture();
        using var request = fixture.Request();
        request.Headers.Remove(Headers.TenantId);
        request.Headers.Add(fixture.Settings.TenantHeader, "attacker");
        Assert.Equal(ForwardedIdentitySigningOutcome.SignatureCreated, fixture.Signer.Sign(request, when_signing_with_explicit_trusted_context.Target()));
        Assert.False(request.Headers.Contains(fixture.Settings.TenantHeader));
    }
}
