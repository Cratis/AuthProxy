// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_an_anonymous_route_passes_the_caller_authorization : given.a_signed_transport
{
    void Establish()
    {
        request.Headers.Clear();
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer callers.own.token");
        request.Headers.Add(Headers.Principal, "forged");
        request.Headers.Add(Headers.PrincipalId, "forged");
        request.Headers.Add(Headers.TenantId, "forged");
        request.Headers.Add(Headers.LegacyTenantId, "forged");
        request.Headers.Add(Headers.OnBehalfActor, "forged");
        request.Headers.Add(Headers.ForwardedIdentitySignature, "forged");
        request.Options.Set(AnonymousPaths.ForwardWithoutIdentity, true);
        request.Options.Set(AnonymousPaths.PassCallerAuthorization, true);
    }

    Task Because() => Send();

    [Fact] void should_forward() => transport.Calls.ShouldEqual(1);
    [Fact] void should_forward_the_exact_authorization_value() => request.Headers.GetValues("Authorization").Single().ShouldEqual("Bearer callers.own.token");
    [Fact] void should_strip_a_forged_principal() => request.Headers.Contains(Headers.Principal).ShouldBeFalse();
    [Fact] void should_strip_a_forged_principal_id() => request.Headers.Contains(Headers.PrincipalId).ShouldBeFalse();
    [Fact] void should_strip_a_forged_tenant() => request.Headers.Contains(Headers.TenantId).ShouldBeFalse();
    [Fact] void should_strip_a_forged_legacy_tenant() => request.Headers.Contains(Headers.LegacyTenantId).ShouldBeFalse();
    [Fact] void should_strip_a_forged_actor() => request.Headers.Contains(Headers.OnBehalfActor).ShouldBeFalse();
    [Fact] void should_strip_a_forged_signature() => proof.ShouldBeNull();
}
