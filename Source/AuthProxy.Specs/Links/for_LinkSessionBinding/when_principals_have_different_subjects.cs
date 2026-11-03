// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSessionBinding;

public class when_principals_have_different_subjects : Specification
{
    string _first;
    string _second;

    void Because()
    {
        LinkSessionBinding.TryCreate(Principal("account-1"), out _first);
        LinkSessionBinding.TryCreate(Principal("account-2"), out _second);
    }

    static ClaimsPrincipal Principal(string subject) =>
        new(new ClaimsIdentity([new Claim("sub", subject), new Claim(SessionClaims.ProviderScheme, "microsoft")], "Cookies"));

    [Fact] void should_give_different_bindings() => _first.ShouldNotEqual(_second);
}
