// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_Headers;

/// <summary>
/// The header names are a contract with every backend and frontend behind the proxy, so they are pinned by
/// value. AuthProxy adopts the names Arc uses by default — an Arc application behind it needs no tenancy
/// or microservice configuration — and keeps the previous names only where a client could still be sending
/// them, to accept them for service selection and to strip them for the tenant.
/// </summary>
public class when_naming_the_headers : Specification
{
    [Fact] void should_forward_the_tenant_as_the_name_arc_resolves_by_default() => Headers.TenantId.ShouldEqual("x-cratis-tenant-id");
    [Fact] void should_select_the_service_by_the_name_arc_sends_by_default() => Headers.ServiceId.ShouldEqual("x-cratis-microservice");
    [Fact] void should_know_the_previous_tenant_name() => Headers.LegacyTenantId.ShouldEqual("Tenant-ID");
    [Fact] void should_know_the_previous_service_name() => Headers.LegacyServiceId.ShouldEqual("Service-ID");
    [Fact] void should_match_identity_headers_by_the_platform_prefix() => Headers.PrincipalPrefix.ShouldEqual("x-ms-client-principal");
}
