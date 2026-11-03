// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Links.for_LinkSessionBinding;

public class when_principals_signed_in_with_different_providers : Specification
{
    string _first;
    string _second;

    void Because()
    {
        LinkSessionBinding.TryCreate(Principal("microsoft"), out _first);
        LinkSessionBinding.TryCreate(Principal("github"), out _second);
    }

    static ClaimsPrincipal Principal(string scheme) =>
        new(new ClaimsIdentity([new Claim("sub", "account-1"), new Claim(SessionClaims.ProviderScheme, scheme)], "Cookies"));

    [Fact] void should_give_different_bindings() => _first.ShouldNotEqual(_second);
}
