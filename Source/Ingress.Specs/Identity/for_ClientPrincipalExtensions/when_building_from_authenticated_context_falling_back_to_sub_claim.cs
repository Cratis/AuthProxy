// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Identity.for_ClientPrincipalExtensions;

public class when_building_from_authenticated_context_falling_back_to_sub_claim : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        _context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
        [
            new Claim("sub", "subject-id"),
            new Claim("name", "John Doe")
        ],
        "jwt");
        _context.User = new ClaimsPrincipal(identity);
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_return_a_principal() => Assert.NotNull(_result);
    [Fact] void should_use_sub_as_user_id() => Assert.Equal("subject-id", _result!.UserId);
    [Fact] void should_use_name_claim_as_user_details() => Assert.Equal("John Doe", _result!.UserDetails);
}
