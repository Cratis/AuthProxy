// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Tenancy.for_CredentialTarget;

public class when_comparing_constraints : Specification
{
    [Theory]
    [InlineData("tenant-a", "tenant-a", true)]
    [InlineData("Tenant-A", "tenant-a", false)]
    [InlineData("tenant-a ", "tenant-a", false)]
    [InlineData(" tenant-a", "tenant-a", false)]
    [InlineData("", "tenant-a", false)]
    public void should_compare_exactly(string credential, string target, bool matches) =>
        CredentialTarget.Matches(credential, target).ShouldEqual(matches);

    [Theory]
    [InlineData("tenant-a", "tenant-a", true)]
    [InlineData("Tenant-A", "tenant-a", true)]
    [InlineData("tenant-a ", "tenant-a", false)]
    [InlineData(" tenant-a", "tenant-a", false)]
    [InlineData("tenant-a", "tenant-b", false)]
    public void should_compare_tenants_ignoring_only_case(string credential, string target, bool matches) =>
        CredentialTarget.MatchesTenant(credential, target).ShouldEqual(matches);

    [Theory]
    [InlineData(C.TenantSourceIdentifierResolverType.Host, true, true)]
    [InlineData(C.TenantSourceIdentifierResolverType.SubHost, true, true)]
    [InlineData(C.TenantSourceIdentifierResolverType.Route, true, true)]
    [InlineData(C.TenantSourceIdentifierResolverType.Specified, true, false)]
    [InlineData(C.TenantSourceIdentifierResolverType.Specified, false, true)]
    [InlineData(C.TenantSourceIdentifierResolverType.Default, false, false)]
    [InlineData(C.TenantSourceIdentifierResolverType.Claim, false, false)]
    [InlineData(C.TenantSourceIdentifierResolverType.Selection, false, false)]
    [InlineData(C.TenantSourceIdentifierResolverType.None, false, false)]
    public void should_only_treat_addressing_strategies_as_targets(C.TenantSourceIdentifierResolverType strategy, bool bearerRoute, bool addressed) =>
        CredentialTarget.IsAddressedByRequest(strategy, bearerRoute).ShouldEqual(addressed);
}
