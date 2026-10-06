// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSubjectExchanger;

public class when_exchanging_a_canonical_oidc_subject : given.a_canonical_link_subject_exchanger
{
    LinkExchangeResult _result;

    protected override C.AuthProxy CreateConfig() => new()
    {
        Link = new C.Link { ExchangeUrl = ExchangeUrl },
        Authentication = CanonicalOidcFixture.Configuration(),
    };

    protected override ClaimsPrincipal CreatePrincipal() => CanonicalOidcFixture.Principal();

    async Task Because() => _result = await _exchanger.Exchange(_principal, _properties, "workforce");

    [Fact] void should_exchange() => _result.ShouldEqual(LinkExchangeResult.Success);
    [Fact] void should_post_the_canonical_subject() => _handler.LastRequestBody!.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _handler.LastRequestBody!.ShouldContain("\"providerKey\":\"workforce\"");
}
