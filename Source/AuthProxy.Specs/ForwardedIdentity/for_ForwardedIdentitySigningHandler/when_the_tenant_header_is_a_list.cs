// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySigningHandler;

public class when_the_tenant_header_is_a_list : given.a_signed_transport
{
    void Establish() => request.Headers.TryAddWithoutValidation(Headers.LegacyTenantId, "acme,acme");

    Task Because() => Send();

    [Fact] void should_not_contact_the_backend() => transport.Calls.ShouldEqual(0);
    [Fact] void should_report_a_typed_failure() => exception.ShouldBeOfExactType<TenantHeaderIsAmbiguous>();
}
