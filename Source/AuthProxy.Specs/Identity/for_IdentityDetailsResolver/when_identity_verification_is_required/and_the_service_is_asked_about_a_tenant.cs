// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.Arc.Identity;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.when_identity_verification_is_required;

/// <summary>
/// The tenant is sent to the service's identity endpoint as <c language="text">x-cratis-tenant-id</c>, the name an Arc service
/// resolves its tenant from by default, so the endpoint answers about the tenant the proxy resolved and not
/// about whichever one the application's own settings fall back to. The legacy name carries the same
/// resolved value for existing backends during the transition.
/// </summary>
public class and_the_service_is_asked_about_a_tenant : given.a_required_verification_resolver
{
    IdentityProviderResult _result;
    HttpRequestMessage? _asked;

    void Establish() => _handler.Respond = (request, _, _) =>
    {
        _asked = request;
        return Task.FromResult(Response(System.Net.HttpStatusCode.OK, PositiveBody));
    };

    async Task Because() => _result = await _resolver.Resolve(_context, Principal(), TenantId);

    [Fact] void should_be_authorized() => _result.IsAuthorized.ShouldBeTrue();
    [Fact] void should_send_the_tenant_as_the_name_arc_resolves_by_default() => _asked!.Headers.GetValues("x-cratis-tenant-id").Single().ShouldEqual(TenantId);
    [Fact] void should_send_the_same_tenant_under_the_legacy_name() => _asked!.Headers.GetValues("Tenant-ID").Single().ShouldEqual(TenantId);
}
