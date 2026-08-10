// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// The counterpart to <see cref="when_the_caller_name_is_not_ascii"/>, and the reason the encoding is
/// applied conditionally rather than always: an existing deployment must see the identity headers it has
/// always seen, byte for byte, with nothing added. Backends parse these headers, and a proxy that started
/// sending <c>UTF-8''user%40example.com</c> to everyone would break every one of them at once.
/// <para>
/// Asserted against the header dictionary the origin actually recorded, so the claim is about what went
/// over the socket rather than about what the transform intended.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_the_caller_name_is_ascii(SecurityHarness harness) : IAsyncLifetime
{
    readonly string _user = SecurityHarness.UniqueUser("ascii-name");

    ForwardedRequest? _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        harness.Origin.Clear();
        await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath, _user));
        _forwarded = harness.Origin.LastRequestTo(SecurityHarness.ProtectedPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_reach_the_origin() => Assert.NotNull(_forwarded);

    [Fact]
    public void should_send_the_name_verbatim() =>
        Assert.Equal(_user, _forwarded!.Value(Headers.PrincipalName), StringComparer.Ordinal);

    [Fact]
    public void should_send_the_principal_id_verbatim() =>
        Assert.Equal(_user, _forwarded!.Value(Headers.PrincipalId), StringComparer.Ordinal);

    [Fact]
    public void should_send_the_tenant_verbatim() =>
        Assert.Equal(SecurityHarness.TenantId, _forwarded!.Value(Headers.TenantId), StringComparer.Ordinal);

    [Fact]
    public void should_add_no_sibling_header() =>
        Assert.False(_forwarded!.Has(Headers.PrincipalNameExtended));

    [Fact]
    public void should_send_exactly_the_identity_headers_it_always_did() =>
        Assert.Equal(
            [Headers.Principal, Headers.PrincipalId, Headers.PrincipalName],
            _forwarded!.Headers.Keys
                .Where(name => name.StartsWith("x-ms-", StringComparison.OrdinalIgnoreCase))
                .Order(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);
}
