// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ExternalTokenTenantBinding;

public class when_resolving_the_token_tenant : Specification
{
    [Theory]
    [InlineData("tenant-a", true)]
    [InlineData("Tenant-A", true)]
    [InlineData("", false)]
    [InlineData(" ", false)]
    [InlineData(" tenant-a", false)]
    [InlineData("tenant-a ", false)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("tenant/a", false)]
    public void should_require_an_exact_usable_value(string value, bool expected) =>
        ExternalTokenTenantBinding.TryResolveTenant([new("tid", value)], new(), out _).ShouldEqual(expected);

    [Fact]
    public void should_reject_a_missing_claim() =>
        ExternalTokenTenantBinding.TryResolveTenant([], new(), out _).ShouldBeFalse();

    [Fact]
    public void should_reject_multiple_identical_claims() =>
        ExternalTokenTenantBinding.TryResolveTenant([new("tid", "tenant-a"), new("tid", "tenant-a")], new(), out _).ShouldBeFalse();

    [Fact]
    public void should_not_match_a_case_variant_claim_type() =>
        ExternalTokenTenantBinding.TryResolveTenant([new("TID", "tenant-a")], new(), out _).ShouldBeFalse();

    [Fact]
    public void should_support_an_exact_custom_claim_type()
    {
        ExternalTokenTenantBinding.TryResolveTenant([new("tenant", "tenant-a")], new() { TenantClaimType = "tenant" }, out var tenant).ShouldBeTrue();
        tenant.ShouldEqual("tenant-a");
    }

    [Theory]
    [InlineData("external-a", true)]
    [InlineData("External-a", false)]
    [InlineData("external-a ", false)]
    [InlineData("tenant-a", false)]
    public void should_treat_a_nonempty_mapping_as_an_exact_allowlist(string value, bool expected)
    {
        var settings = new C.ExternalTokenTenantBinding
        {
            TenantMapping = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["external-a"] = "tenant-a" },
        };
        ExternalTokenTenantBinding.TryResolveTenant([new("tid", value)], settings, out var tenant).ShouldEqual(expected);
        if (expected) tenant.ShouldEqual("tenant-a");
    }

    [Fact]
    public void should_reject_an_overlong_direct_tenant() =>
        ExternalTokenTenantBinding.TryResolveTenant([new("tid", new string('a', TenantIdentifier.MaximumLength + 1))], new(), out _).ShouldBeFalse();
}
