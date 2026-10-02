// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Security.for_BearerRoutes;

/// <summary>
/// Everything the validation rules say about the token's shape holds end to end: an ID token (any
/// <c language="text">typ</c> but an access-token type), an HMAC token keyed with the issuer's public key, a token without an
/// expiry, an encrypted token and a token missing a claim a mapping reads are refused as invalid; a token naming
/// more than one tenant, or a tenant that is not a plain identifier, is refused as forbidden. None is forwarded.
/// </summary>
/// <param name="harness">The running proxy, origin and issuer.</param>
[Collection(BearerRouteSpecCollection.Name)]
public class when_the_token_is_not_an_acceptable_access_token(BearerRouteHarness harness) : IAsyncLifetime
{
    const string Path = $"{BearerRouteHarness.RoutePrefix}/unacceptable";

    HttpResponseMessage? _idToken;
    HttpResponseMessage? _publicKeyAsSecret;
    HttpResponseMessage? _withoutExpiry;
    HttpResponseMessage? _encrypted;
    HttpResponseMessage? _withoutMappedSource;
    HttpResponseMessage? _twoTenants;
    HttpResponseMessage? _unusableTenant;
    bool _forwarded;

    public async Task InitializeAsync()
    {
        using var client = harness.CreateBearerClient();
        harness.Origin.Clear();

        _idToken = await Send(client, harness.Issuer.TokenShaped(_ => _.TokenType = JwtConstants.HeaderType));
        _publicKeyAsSecret = await Send(client, harness.Issuer.TokenSignedWithThePublicKeyAsASecret());
        _withoutExpiry = await Send(client, harness.Issuer.TokenShaped(_ => _.Expires = null, setDefaultTimes: false));
        _encrypted = await Send(client, harness.Issuer.TokenShaped(_ => _.EncryptingCredentials = new EncryptingCredentials(
            new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(64)),
            JwtConstants.DirectKeyUseAlg,
            SecurityAlgorithms.Aes256CbcHmacSha512)));
        _withoutMappedSource = await Send(client, harness.Issuer.Token(without: "github_id"));
        _twoTenants = await Send(client, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = new[] { BearerRouteHarness.TenantId, "33333333-3333-3333-3333-333333333333" } }));
        _unusableTenant = await Send(client, harness.Issuer.Token(new Dictionary<string, object> { ["tid"] = "../other tenant" }));
        _forwarded = harness.Origin.ReceivedAnythingFor(Path);
    }

    public Task DisposeAsync()
    {
        _idToken?.Dispose();
        _publicKeyAsSecret?.Dispose();
        _withoutExpiry?.Dispose();
        _encrypted?.Dispose();
        _withoutMappedSource?.Dispose();
        _twoTenants?.Dispose();
        _unusableTenant?.Dispose();
        return Task.CompletedTask;
    }

    [Fact] public void should_refuse_an_id_token() => Assert.Equal(HttpStatusCode.Unauthorized, _idToken!.StatusCode);
    [Fact] public void should_refuse_an_hmac_token_keyed_with_the_public_key() => Assert.Equal(HttpStatusCode.Unauthorized, _publicKeyAsSecret!.StatusCode);
    [Fact] public void should_refuse_a_token_without_an_expiry() => Assert.Equal(HttpStatusCode.Unauthorized, _withoutExpiry!.StatusCode);
    [Fact] public void should_refuse_an_encrypted_token() => Assert.Equal(HttpStatusCode.Unauthorized, _encrypted!.StatusCode);
    [Fact] public void should_refuse_a_token_missing_a_mapped_claim() => Assert.Equal(HttpStatusCode.Unauthorized, _withoutMappedSource!.StatusCode);
    [Fact] public void should_refuse_a_token_naming_two_tenants() => Assert.Equal(HttpStatusCode.Forbidden, _twoTenants!.StatusCode);
    [Fact] public void should_refuse_a_tenant_that_is_not_a_plain_identifier() => Assert.Equal(HttpStatusCode.Forbidden, _unusableTenant!.StatusCode);
    [Fact] public void should_forward_none_of_them() => Assert.False(_forwarded);

    static Task<HttpResponseMessage> Send(HttpClient client, string token) =>
        client.SendAsync(BearerRouteHarness.WithToken(HttpMethod.Get, Path, token));
}
