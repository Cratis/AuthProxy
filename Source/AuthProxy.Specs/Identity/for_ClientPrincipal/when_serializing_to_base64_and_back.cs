// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_ClientPrincipal;

public class when_serializing_to_base64_and_back : Specification
{
    ClientPrincipal _original;
    string _base64;
    ClientPrincipal? _result;
    bool _succeeded;

    void Establish()
    {
        _original = new ClientPrincipal
        {
            IdentityProvider = "aad",
            UserId = "user-123",
            UserDetails = "user@example.com",
            UserRoles = ["anonymous", "authenticated", "admin"],
            Claims = [new ClientPrincipalClaim { Type = "tid", Value = "tenant-abc" }]
        };
    }

    void Because()
    {
        _base64 = _original.ToBase64();
        _succeeded = ClientPrincipal.TryFromBase64(_base64, out _result);
    }

    [Fact] void should_succeed() => Assert.True(_succeeded);
    [Fact] void should_restore_identity_provider() => Assert.Equal(_original.IdentityProvider, _result!.IdentityProvider);
    [Fact] void should_restore_user_id() => Assert.Equal(_original.UserId, _result!.UserId);
    [Fact] void should_restore_user_details() => Assert.Equal(_original.UserDetails, _result!.UserDetails);
    [Fact] void should_restore_roles() => Assert.Equal(_original.UserRoles, _result!.UserRoles);
    [Fact] void should_restore_claims() => Assert.Single(_result!.Claims);
    [Fact] void should_restore_claim_type() => Assert.Equal("tid", _result!.Claims.First().Type);
    [Fact] void should_restore_claim_value() => Assert.Equal("tenant-abc", _result!.Claims.First().Value);
    [Fact] void should_produce_non_empty_base64() => Assert.NotEmpty(_base64);
}
