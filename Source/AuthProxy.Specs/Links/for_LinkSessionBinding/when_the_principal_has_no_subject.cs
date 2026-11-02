// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSessionBinding;

public class when_the_principal_has_no_subject : Specification
{
    bool _created;
    bool _createdForNull;

    void Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(SessionClaims.ProviderScheme, "microsoft"), new Claim("sub", "  ")],
            "Cookies"));
        _created = LinkSessionBinding.TryCreate(principal, out _);
        _createdForNull = LinkSessionBinding.TryCreate(null, out _);
    }

    [Fact] void should_not_create_a_binding() => _created.ShouldBeFalse();
    [Fact] void should_not_create_a_binding_without_a_principal() => _createdForNull.ShouldBeFalse();
}
