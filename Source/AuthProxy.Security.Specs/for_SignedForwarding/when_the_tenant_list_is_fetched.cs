// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Security.for_SignedForwarding;

/// <summary>
/// The call AuthProxy makes to the tenant-selection endpoint carries the caller's identity, so it is signed, for the
/// audience of the service whose backend serves the endpoint.
/// </summary>
/// <param name="harness">The running signing proxy and its origin, which serves the tenant endpoint.</param>
[Collection(SignedTenantSelectionSpecCollection.Name)]
public class when_the_tenant_list_is_fetched(SignedTenantSelectionHarness harness) : IAsyncLifetime
{
    HttpResponseMessage? _response;
    ForwardedRequest? _tenantsCall;
    ForwardedAssertion? _assertion;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateSecurityClient();
        harness.Origin.Clear();

        _response = await client.SendAsync(SecurityHarness.Authenticated(HttpMethod.Get, SecurityHarness.ProtectedPath, SecurityHarness.UniqueUser("signed-selection")));
        _tenantsCall = harness.Origin.LastRequestTo(SignedTenantSelectionHarness.TenantsPath);
        _assertion = ForwardedAssertion.From(_tenantsCall);
    }

    public Task DisposeAsync()
    {
        _response?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_call_the_tenant_endpoint() => Assert.NotNull(_tenantsCall);
    [Fact] public void should_attach_an_assertion() => Assert.NotNull(_assertion);
    [Fact] public void should_verify_with_the_pinned_public_key() => Assert.True(_assertion!.VerifiesWith(harness.Key.PublicKeyPem));
    [Fact] public void should_be_for_the_audience_of_the_serving_service() => Assert.Equal("app", _assertion!.Claim("aud"));
    [Fact] public void should_bind_the_method() => Assert.Equal("GET", _assertion!.Claim("htm"));
    [Fact] public void should_bind_the_tenant_endpoint_path() => Assert.Equal(SignedTenantSelectionHarness.TenantsPath, _assertion!.Claim("htp"));
    [Fact] public void should_carry_the_caller_as_subject() => Assert.Equal(_tenantsCall!.Value(Headers.PrincipalId), _assertion!.Claim("sub"));
}
