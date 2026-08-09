// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Links.for_LinkSubjectExchanger.given;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_exchanging_a_canonical_subject : a_canonical_link_subject_exchanger
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
                        Issuer = "https://identity.example.com/"
                    }
                }
            ]
        }
    };

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("oid", "configured-subject"),
        new Claim("sub", "old-sub"),
    ],
    "github"));

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties);

    [Fact] void should_succeed() => _result.ShouldEqual(LinkExchangeResult.Success);
    [Fact] void should_post_the_configured_subject() => _handler.LastRequestBody!.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _handler.LastRequestBody!.ShouldContain("\"providerKey\":\"workforce\"");
    [Fact] void should_post_the_normalized_issuer() => _handler.LastRequestBody!.ShouldContain("\"issuer\":\"https://identity.example.com\"");
    [Fact] void should_not_post_an_old_fallback_subject() => _handler.LastRequestBody!.ShouldNotContain("old-sub");
}
