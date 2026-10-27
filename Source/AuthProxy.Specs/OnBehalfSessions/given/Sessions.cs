// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions.given;

/// <summary>
/// The actors, represented users and sessions the specs share.
/// </summary>
public static class Sessions
{
    public const string Tenant = "11111111-1111-1111-1111-111111111111";
    public const string Subject = "represented-user";
    public const string Issue = "ISSUE-42";
    public const string ActorProvider = "github";
    public const string ActorSubject = "support-person";
    public const string ActorName = "support@example.com";

    public static OnBehalfActor Actor { get; } = new(ActorProvider, ActorSubject, ActorName);

    public static OnBehalfSession At(DateTimeOffset startedAt, string sessionId = "session-1") =>
        new(sessionId, Actor, Tenant, Subject, Issue, startedAt, startedAt.AddHours(1));

    public static ClientPrincipal Represented() => new()
    {
        IdentityProvider = "microsoft",
        UserId = Subject,
        UserDetails = "user@example.com",
        UserRoles = ["user", "anonymous", "authenticated"],
    };

    public static ClaimsPrincipal ActorPrincipal(string subject = ActorSubject, bool support = true)
    {
        var claims = new List<Claim> { new("sub", subject), new("email", ActorName) };
        if (support)
        {
            claims.Add(new Claim(OnBehalfConfiguration.SupportClaim, OnBehalfConfiguration.SupportRole));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, ActorProvider));
    }
}
