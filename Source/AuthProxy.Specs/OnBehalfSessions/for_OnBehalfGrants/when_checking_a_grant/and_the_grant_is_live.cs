// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.given;
using Cratis.AuthProxy.OnBehalfSessions.given;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfGrants.when_checking_a_grant;

public class and_the_grant_is_live : a_grant_check
{
    Dictionary<string, Microsoft.Extensions.Primitives.StringValues> _query;
    JsonWebToken _token;

    protected override string? Body => LiveAnswer();

    async Task Because()
    {
        await Check();
        _query = QueryHelpers.ParseQuery(_handler.LastRequest!.RequestUri!.Query);
        _token = new JsonWebTokenHandler().ReadJsonWebToken(_handler.LastAuthorization!["Bearer ".Length..]);
    }

    [Fact] void should_be_live() => _result.IsLive.ShouldBeTrue();
    [Fact] void should_carry_the_valid_until() => _result.ValidUntil.ShouldEqual(new DateTimeOffset(2026, 9, 1, 13, 0, 0, TimeSpan.Zero));
    [Fact] void should_identify_the_represented_user() => _result.Principal!.UserId.ShouldEqual(Sessions.Subject);
    [Fact] void should_keep_the_represented_users_roles() => _result.Principal!.UserRoles.ShouldContain("user");
    [Fact] void should_add_the_built_in_roles() => _result.Principal!.UserRoles.ShouldContain("authenticated");
    [Fact] void should_keep_the_represented_users_claims() => _result.Principal!.Claims.Any(_ => _.Type == "tid").ShouldBeTrue();
    [Fact] void should_drop_claims_in_the_bearer_route_namespace() => _result.Principal!.Claims.Any(_ => _.Type.StartsWith("urn:cratis:bearer:", StringComparison.Ordinal)).ShouldBeFalse();
    [Fact] void should_get_the_grant_endpoint() => _handler.LastRequest!.RequestUri!.AbsolutePath.ShouldEqual(WellKnownPaths.OnBehalfGrants);
    [Fact] void should_ask_about_the_subject() => _query["subject"].ToString().ShouldEqual(Sessions.Subject);
    [Fact] void should_ask_about_the_issue() => _query["issue"].ToString().ShouldEqual(Sessions.Issue);
    [Fact] void should_ask_about_the_actor() => _query["actor"].ToString().ShouldEqual(Sessions.ActorSubject);
    [Fact] void should_ask_about_the_session() => _query["session"].ToString().ShouldEqual(_session.SessionId);
    [Fact] void should_send_the_tenant() => _handler.LastHeaders[Headers.TenantId].ShouldEqual(Sessions.Tenant);
    [Fact] void should_send_the_actor() => _handler.LastHeaders[Headers.OnBehalfActor].ShouldEqual(_actor.ToBase64());
    [Fact] void should_not_send_any_principal_as_the_user() => _handler.LastHeaders.ContainsKey(Headers.Principal).ShouldBeFalse();
    [Fact] void should_sign_it_for_the_grant_check() => _token.GetClaim(OnBehalfAttestationClaims.Purpose).Value.ShouldEqual(OnBehalfAttestationClaims.GrantCheckPurpose);
    [Fact] void should_sign_the_empty_body() => _token.GetClaim(OnBehalfAttestationClaims.BodyHash).Value.ShouldEqual(Base64UrlEncoder.Encode(SHA256.HashData([])));
}
