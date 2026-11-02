// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSessionBinding;

public class when_two_principals_have_the_same_account : Specification
{
    string _first;
    string _second;
    bool _firstCreated;
    bool _secondCreated;

    void Because()
    {
        _firstCreated = LinkSessionBinding.TryCreate(Principal("account-1", "microsoft", "alpha@example.com"), out _first);
        _secondCreated = LinkSessionBinding.TryCreate(Principal("account-1", "microsoft", "beta@example.com"), out _second);
    }

    static ClaimsPrincipal Principal(string subject, string scheme, string email) =>
        new(new ClaimsIdentity(
            [new Claim("sub", subject), new Claim(SessionClaims.ProviderScheme, scheme), new Claim(ClaimTypes.Email, email)],
            "Cookies"));

    [Fact] void should_create_both_bindings() => (_firstCreated && _secondCreated).ShouldBeTrue();
    [Fact] void should_give_equal_bindings() => _first.ShouldEqual(_second);
}
