// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_a_covered_header_changes_after_signing : given.the_published_vector
{
    Dictionary<string, bool> _invalidated;
    bool _additionInvalidated;
    bool _removalInvalidated;

    void Because()
    {
        string[] names = [Headers.Principal, Headers.PrincipalId, Headers.PrincipalName, Headers.PrincipalNameExtended,
            Headers.TenantId, Headers.LegacyTenantId, Headers.ServiceId, Headers.LegacyServiceId,
            Headers.TokenClientId, Headers.TokenScope, Headers.OnBehalfActor, Headers.OnBehalfAssertion];
        foreach (var name in names.Where(name => !request.Headers.Contains(name))) request.Headers.Add(name, "original");
        Canonicalize();
        var original = mac;
        _invalidated = new();
        foreach (var name in names)
        {
            var value = request.Headers.GetValues(name).Single();
            request.Headers.Remove(name);
            request.Headers.Add(name, "changed");
            Canonicalize();
            _invalidated[name] = mac != original;
            request.Headers.Remove(name);
            request.Headers.Add(name, value);
        }
        request.Headers.Add("x-ms-client-principal-extra", "extra");
        Canonicalize();
        _additionInvalidated = mac != original;
        request.Headers.Remove("x-ms-client-principal-extra");
        request.Headers.Remove(Headers.TokenScope);
        Canonicalize();
        _removalInvalidated = mac != original;
    }

    [Fact] void should_invalidate_when_principal_changes() => _invalidated[Headers.Principal].ShouldBeTrue();
    [Fact] void should_invalidate_when_principal_id_changes() => _invalidated[Headers.PrincipalId].ShouldBeTrue();
    [Fact] void should_invalidate_when_principal_name_changes() => _invalidated[Headers.PrincipalName].ShouldBeTrue();
    [Fact] void should_invalidate_when_principal_name_extended_changes() => _invalidated[Headers.PrincipalNameExtended].ShouldBeTrue();
    [Fact] void should_invalidate_when_tenant_changes() => _invalidated[Headers.TenantId].ShouldBeTrue();
    [Fact] void should_invalidate_when_legacy_tenant_changes() => _invalidated[Headers.LegacyTenantId].ShouldBeTrue();
    [Fact] void should_invalidate_when_service_changes() => _invalidated[Headers.ServiceId].ShouldBeTrue();
    [Fact] void should_invalidate_when_legacy_service_changes() => _invalidated[Headers.LegacyServiceId].ShouldBeTrue();
    [Fact] void should_invalidate_when_client_id_changes() => _invalidated[Headers.TokenClientId].ShouldBeTrue();
    [Fact] void should_invalidate_when_scope_changes() => _invalidated[Headers.TokenScope].ShouldBeTrue();
    [Fact] void should_invalidate_when_actor_changes() => _invalidated[Headers.OnBehalfActor].ShouldBeTrue();
    [Fact] void should_invalidate_when_assertion_changes() => _invalidated[Headers.OnBehalfAssertion].ShouldBeTrue();
    [Fact] void should_invalidate_when_a_covered_header_is_added() => _additionInvalidated.ShouldBeTrue();
    [Fact] void should_invalidate_when_a_covered_header_is_removed() => _removalInvalidated.ShouldBeTrue();
}
