// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_the_configured_canonical_subject_is_missing : a_canonical_link_subject_exchanger
{
    LinkExchangeResult _result;

    protected override C.AuthProxy CreateConfig() => new()
    {
        Link = new C.Link { ExchangeUrl = ExchangeUrl },
        Authentication = new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider
                {
                    Name = "GitHub",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid",
                        Issuer = "https://identity.example.com"
                    }
                }
            ]
        }
    };

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", "old-sub"),
        new Claim("email", "person@example.com")
    ],
    "github"));

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties);

    [Fact] void should_fail_closed() => _result.ShouldEqual(LinkExchangeResult.Failed);
    [Fact] void should_not_call_the_exchange() => _handler.LastRequest.ShouldBeNull();
}
