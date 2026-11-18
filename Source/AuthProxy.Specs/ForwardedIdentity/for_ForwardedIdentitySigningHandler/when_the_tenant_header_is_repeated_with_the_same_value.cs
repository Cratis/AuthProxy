// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_the_tenant_header_is_repeated_with_the_same_value : given.a_signed_transport
{
    void Establish()
    {
        request.Headers.Add(Headers.TenantId, "acme");
        request.Headers.Add(Headers.TenantId, "acme");
        request.Headers.Add(Headers.LegacyTenantId, "acme");
        request.Headers.Add(Headers.LegacyTenantId, "acme");
    }

    Task Because() => Send();

    [Fact] void should_forward_the_request() => transport.Calls.ShouldEqual(1);
    [Fact] void should_send_the_tenant_once() => request.Headers.GetValues(Headers.TenantId).ShouldEqual(["acme"]);
    [Fact] void should_send_the_legacy_tenant_once() => request.Headers.GetValues(Headers.LegacyTenantId).ShouldEqual(["acme"]);
}
