// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_AccessControl;

/// <summary>
/// OWASP A01 — Broken Access Control. A caller must not be able to tell the origin who they are.
/// <para>
/// AuthProxy's entire value is that a backend can trust <c>x-ms-client-principal</c>,
/// <c>x-ms-client-principal-id</c>, <c>x-ms-client-principal-name</c> and <c>Tenant-ID</c> as proof of
/// identity, because the proxy is the only thing that writes them. If an inbound copy survived to the
/// origin, every backend behind the proxy would be authenticating whoever asked — the single worst failure
/// this component can have, and one no client-facing response would reveal. So the assertion is made
/// against a real origin that records what it actually received.
/// </para>
/// <para>
/// Asserted on both an anonymous and an authenticated caller, and on the declared anonymous path as well
/// as the ordinary one: the anonymous path is the route that skips the authorization policy, so it is the
/// one where a spoofed header would most plausibly be carried through.
/// </para>
/// </summary>
/// <param name="harness">The running proxy and its origin.</param>
[Collection(SecuritySpecCollection.Name)]
public class when_identity_headers_are_spoofed(SecurityHarness harness) : IAsyncLifetime
{
    ForwardedRequest? _anonymousOnAnonymousPath;
    ForwardedRequest? _authenticatedOnProtectedPath;
    string _injectedPrincipal = string.Empty;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();

        _injectedPrincipal = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """{"userId":"attacker","userRoles":["Administrator"]}"""));

        harness.Origin.Clear();
        await client.SendAsync(Spoofed(SecurityHarness.Anonymous(HttpMethod.Get, SecurityHarness.AnonymousPath)));
        _anonymousOnAnonymousPath = harness.Origin.LastRequestTo(SecurityHarness.AnonymousPath);

        harness.Origin.Clear();
        await client.SendAsync(Spoofed(SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath)));
        _authenticatedOnProtectedPath = harness.Origin.LastRequestTo(SecurityHarness.ProtectedPath);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact] public void should_forward_the_anonymous_request() => Assert.NotNull(_anonymousOnAnonymousPath);
    [Fact] public void should_forward_the_authenticated_request() => Assert.NotNull(_authenticatedOnProtectedPath);

    [Fact]
    public void should_not_carry_a_spoofed_principal_to_the_origin_for_an_anonymous_caller() =>
        Assert.DoesNotContain(_injectedPrincipal, _anonymousOnAnonymousPath!.Value(Headers.Principal), StringComparison.Ordinal);

    [Fact]
    public void should_not_carry_a_spoofed_principal_to_the_origin_for_an_authenticated_caller() =>
        Assert.DoesNotContain(_injectedPrincipal, _authenticatedOnProtectedPath!.Value(Headers.Principal), StringComparison.Ordinal);

    [Fact]
    public void should_not_carry_a_spoofed_principal_id_for_an_anonymous_caller() =>
        Assert.NotEqual("attacker", _anonymousOnAnonymousPath!.Value(Headers.PrincipalId), StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_not_carry_a_spoofed_principal_id_for_an_authenticated_caller() =>
        Assert.NotEqual("attacker", _authenticatedOnProtectedPath!.Value(Headers.PrincipalId), StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_not_carry_a_spoofed_principal_name_for_an_anonymous_caller() =>
        Assert.NotEqual("attacker", _anonymousOnAnonymousPath!.Value(Headers.PrincipalName), StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_not_carry_a_spoofed_tenant_for_an_anonymous_caller() =>
        Assert.NotEqual("victim-tenant", _anonymousOnAnonymousPath!.Value(Headers.TenantId), StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_not_carry_a_spoofed_tenant_for_an_authenticated_caller() =>
        Assert.NotEqual("victim-tenant", _authenticatedOnProtectedPath!.Value(Headers.TenantId), StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void should_give_an_anonymous_caller_no_principal_at_all() =>
        Assert.False(_anonymousOnAnonymousPath!.Has(Headers.Principal));

    /// <summary>
    /// The sibling header is a second, quieter way to tell a backend a name. A caller that could smuggle it
    /// through would be believed by anything that reads the encoded form in preference to the plain one, so
    /// it is stripped exactly like the three it accompanies — and, both callers here having ASCII names,
    /// nothing legitimate replaces it.
    /// </summary>
    [Fact]
    public void should_not_carry_a_spoofed_extended_principal_name_for_an_anonymous_caller() =>
        Assert.False(_anonymousOnAnonymousPath!.Has(Headers.PrincipalNameExtended));

    /// <inheritdoc cref="should_not_carry_a_spoofed_extended_principal_name_for_an_anonymous_caller"/>
    [Fact]
    public void should_not_carry_a_spoofed_extended_principal_name_for_an_authenticated_caller() =>
        Assert.False(_authenticatedOnProtectedPath!.Has(Headers.PrincipalNameExtended));

    static HttpRequestMessage Spoofed(HttpRequestMessage request)
    {
        var forgedPrincipal = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """{"userId":"attacker","userRoles":["Administrator"]}"""));

        request.Headers.TryAddWithoutValidation(Headers.Principal, forgedPrincipal);
        request.Headers.TryAddWithoutValidation(Headers.PrincipalId, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.PrincipalName, "attacker");
        request.Headers.TryAddWithoutValidation(Headers.PrincipalNameExtended, "UTF-8''attacker");
        request.Headers.TryAddWithoutValidation(Headers.TenantId, "victim-tenant");

        return request;
    }
}
