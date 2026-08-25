// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// Configures the callback scenario with signed invitation attestations and matching-tenant lobby bypass disabled.
/// </summary>
public sealed class TenantIssuedLobbyRedirectCallbackAuthProxyFactory : CallbackAuthProxyFactory
{
    const string AttestationKeyId = "callback-spec-key";
    readonly string _attestationPrivateKeyPem = CreatePrivateKeyPem();

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        foreach (var (key, value) in new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Invite:TenantIssuedInvitesSkipLobby"] = bool.FalseString,
            [$"{C.AuthProxy.SectionKey}:Invite:StageUrl"] = StageUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:EmailClaim"] = "email",
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:Issuer"] = "https://authproxy.test",
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:Audience"] = "callback-spec",
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:ActiveKeyId"] = AttestationKeyId,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:SigningKeys:0:KeyId"] = AttestationKeyId,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:SigningKeys:0:PrivateKeyPem"] = _attestationPrivateKeyPem,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:InvitationCompletionEnabled"] = bool.TrueString,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:ProviderKey"] = "testidp",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:SubjectClaimType"] = "sub",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:CanonicalIdentity:Issuer"] = "https://identity.test",
        })
        {
            builder.UseSetting(key, value);
        }
    }

    static string CreatePrivateKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }
}
