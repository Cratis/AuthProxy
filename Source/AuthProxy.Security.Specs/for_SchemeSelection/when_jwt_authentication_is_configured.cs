// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;

namespace Cratis.AuthProxy.Security.for_SchemeSelection;

public class when_jwt_authentication_is_configured
{
    [Theory]
    [InlineData("valid", false)]
    [InlineData("valid", true)]
    [InlineData("invalid", false)]
    [InlineData("invalid", true)]
    [InlineData("expired", false)]
    [InlineData("expired", true)]
    public async Task should_keep_jwt_validation_and_session_selection_separate(string kind, bool withSession)
    {
        await using var harness = new JwtSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        var token = harness.JwtToken();
        if (kind == "invalid") token = token[..^8];
        if (kind == "expired") harness.Clock.Advance(TimeSpan.FromHours(2));
        using var request = withSession
            ? harness.AuthenticatedRequest(RequiredVerificationHarness.ProtectedPath).Message
            : new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        if (kind == "valid" && !withSession)
        {
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(harness.Origin.ReceivedAnythingFor(RequiredVerificationHarness.ProtectedPath));
        }
        else
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Empty(harness.Origin.Received);
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task should_refuse_duplicate_authorization_values(bool jwt, bool combined)
    {
        await using var harness = jwt ? new JwtSelectionHarness() : new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        var token = harness is JwtSelectionHarness jwtHarness ? jwtHarness.JwtToken() : harness.Token();
        using var request = new HttpRequestMessage(HttpMethod.Get, RequiredVerificationHarness.ProtectedPath);
        string[] values = combined ? [$"Bearer {token}, Bearer {token}"] : [$"Bearer {token}", $"Bearer {token}"];
        request.Headers.TryAddWithoutValidation("Authorization", values);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Theory]
    [InlineData(false, WellKnownPaths.IdentityDetails)]
    [InlineData(true, WellKnownPaths.IdentityDetails)]
    [InlineData(false, WellKnownPaths.SelectTenant)]
    [InlineData(true, WellKnownPaths.SelectTenant)]
    public async Task should_refuse_mixed_authentication_on_identity_and_tenant_endpoints(bool jwt, string path)
    {
        await using var harness = jwt ? new JwtSelectionHarness() : new CredentialSelectionHarness();
        using var client = harness.CreateSecurityClient();
        using var request = harness.AuthenticatedRequest(path).Message;
        var token = harness is JwtSelectionHarness jwtHarness ? jwtHarness.JwtToken() : harness.Token();
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
    }

    [Fact]
    public async Task should_keep_the_identity_endpoint_reachable_with_a_session_alone()
    {
        await using var harness = new JwtSelectionHarness();
        harness.VerifyEveryCaller();
        using var client = harness.CreateSecurityClient();
        using var request = harness.AuthenticatedRequest(WellKnownPaths.IdentityDetails).Message;
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
