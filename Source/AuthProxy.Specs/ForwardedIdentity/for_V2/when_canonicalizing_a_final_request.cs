// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Cratis.AuthProxy.ForwardedIdentity.for_V2;

public class when_canonicalizing_a_final_request : Specification
{
    const string Nonce = "AAECAwQFBgcICQoLDA0ODw";

    [Fact]
    public void should_bind_the_actual_escaped_path_and_custom_tenancy_but_not_the_query()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        var context = V2Vector.Context(input) with { TenantHeader = "x-host-tenant" };
        request.RequestUri = new("https://backend.example/a%2fb?excluded=yes");
        request.Headers.Add(context.TenantHeader, "tenant-one");
        Assert.True(Create(request, context, out var first));
        Assert.Contains("6:/a%2Fb\n", Encoding.UTF8.GetString(first), StringComparison.Ordinal);
        request.RequestUri = new("https://backend.example/a%2fb?excluded=no");
        Assert.True(Create(request, context, out var second));
        Assert.Equal(first, second);
        request.Headers.Remove(context.TenantHeader);
        request.Headers.Add(context.TenantHeader, "tenant-two");
        Assert.True(Create(request, context, out var third));
        Assert.NotEqual(first, third);
    }

    [Fact]
    public void should_refuse_covered_duplicates_even_when_hidden_in_content_headers()
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        request.Content = new StringContent(string.Empty);
        request.Content.Headers.TryAddWithoutValidation(Headers.PrincipalId, "different");
        Assert.False(Create(request, V2Vector.Context(input), out _));
    }

    [Theory]
    [InlineData("x-ms-client-principal-extra", "one\ntwo")]
    [InlineData("x-cratis-on-behalf-extra", "non-ascii-\u00e9")]
    public void should_refuse_controls_and_non_ascii_in_every_covered_prefix(string name, string value)
    {
        using var fixture = V2Vector.Load();
        var input = fixture.RootElement.GetProperty("cases")[0].GetProperty("inputs");
        using var request = V2Vector.Request(input);
        request.Headers.TryAddWithoutValidation(name, value);
        Assert.False(Create(request, V2Vector.Context(input), out _));
    }

    static bool Create(HttpRequestMessage request, ForwardedIdentityTrustedContext context, out byte[] bytes) => ForwardedIdentityV2CanonicalInput.TryCreate(request, context, "backend", "key-1", "1700000000", Nonce, out bytes);
}
