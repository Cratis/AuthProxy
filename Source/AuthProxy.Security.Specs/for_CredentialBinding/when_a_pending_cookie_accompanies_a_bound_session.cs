// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.Invites;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Pending flow cookies cannot relax the tenant constraint of a session.</summary>
/// <param name="harness">The addressed deployment.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_a_pending_cookie_accompanies_a_bound_session(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData(Cookies.Registration)]
    [InlineData(Cookies.InviteToken)]
    public async Task should_refuse_a_conflicting_host(string pendingCookie)
    {
        using var client = harness.CreateSecurityClient();
        await Refuse(client, $"{pendingCookie}=x");
    }

    [Fact]
    public async Task should_refuse_even_a_valid_invitation_not_established_by_the_session()
    {
        using var key = RSA.Create(2048);
        await using var deployment = harness.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem"] = key.ExportSubjectPublicKeyInfoPem(),
            })));
        using var client = deployment.CreateClient(new() { AllowAutoRedirect = false, HandleCookies = false });
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key), SecurityAlgorithms.RsaSha256),
            Claims = new Dictionary<string, object> { ["sub"] = "invited-person", ["tid"] = TenantSelectionHarness.TenantB },
        });
        Assert.True(await deployment.Services.GetRequiredService<IInviteTokenValidator>().Validate(token, TestContext.Current.CancellationToken));
        await Refuse(client, $"{Cookies.InviteToken}={token}");
    }

    async Task Refuse(HttpClient client, string pendingCookie)
    {
        harness.UserBelongsTo(TenantSelectionHarness.TenantA, TenantSelectionHarness.TenantB);
        var user = SecurityHarness.UniqueUser("pending-cookie");
        var selection = await harness.SelectTenant(client, user, TenantSelectionHarness.TenantA);
        harness.Origin.Clear();
        using var request = TenantSelectionHarness.Request("/api/pending-binding", user, selection, pendingCookie);
        request.Headers.Host = "b.direct.example.test";
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(harness.Origin.Received);
        Assert.False(response.Headers.Contains(Headers.Principal));
        Assert.False(response.Headers.Contains(Headers.TenantId));
    }
}
