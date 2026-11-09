// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_an_anonymous_route_is_not_listed_for_authorization_passthrough : given.a_signed_transport
{
    void Establish()
    {
        request.Headers.Clear();
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer callers.own.token");
        request.Headers.Add(Headers.TenantId, "forged");
        request.Options.Set(AnonymousPaths.ForwardWithoutIdentity, true);
        request.Options.Set(AnonymousPaths.PassCallerAuthorization, false);
    }

    Task Because() => Send();

    [Fact] void should_forward() => transport.Calls.ShouldEqual(1);
    [Fact] void should_remove_the_authorization_header() => request.Headers.Contains("Authorization").ShouldBeFalse();
    [Fact] void should_strip_a_forged_tenant() => request.Headers.Contains(Headers.TenantId).ShouldBeFalse();
}
