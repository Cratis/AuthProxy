// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.Ingress.Identity.for_ClientPrincipalExtensions;

public class when_building_from_authenticated_context_with_oid_claim : Specification
{
    DefaultHttpContext _context;
    ClientPrincipal? _result;

    void Establish()
    {
        _context = new DefaultHttpContext();
        var identity = new ClaimsIdentity(
        [
            new Claim("oid", "user-object-id"),
            new Claim("preferred_username", "user@example.com"),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim("tid", "tenant-abc")
        ],
        "aad");
        _context.User = new ClaimsPrincipal(identity);
    }

    void Because() => _result = _context.BuildClientPrincipal();

    [Fact] void should_return_a_principal() => Assert.NotNull(_result);
    [Fact] void should_use_oid_as_user_id() => Assert.Equal("user-object-id", _result!.UserId);
    [Fact] void should_use_preferred_username_as_user_details() => Assert.Equal("user@example.com", _result!.UserDetails);
    [Fact] void should_set_identity_provider_from_authentication_type() => Assert.Equal("aad", _result!.IdentityProvider);
    [Fact] void should_include_role_in_roles() => Assert.Contains("admin", _result!.UserRoles);
    [Fact] void should_always_include_anonymous_role() => Assert.Contains("anonymous", _result!.UserRoles);
    [Fact] void should_always_include_authenticated_role() => Assert.Contains("authenticated", _result!.UserRoles);
    [Fact] void should_include_non_role_claims() => Assert.Contains(_result!.Claims, c => c.Type == "tid" && c.Value == "tenant-abc");
    [Fact] void should_not_include_role_claims_in_claims_collection() => Assert.DoesNotContain(_result!.Claims, c => c.Type == ClaimTypes.Role);
}
