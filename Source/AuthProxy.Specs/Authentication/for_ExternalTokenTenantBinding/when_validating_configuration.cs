// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Authentication.for_ExternalTokenTenantBinding;

public class when_validating_configuration : Specification
{
    [Theory]
    [InlineData(true, "tid", "tenant-a", true)]
    [InlineData(false, "tid", "tenant-a", false)]
    [InlineData(true, "", "tenant-a", false)]
    [InlineData(true, " ", "tenant-a", false)]
    [InlineData(true, "tid", "", false)]
    [InlineData(true, "tid", "../tenant", false)]
    [InlineData(true, "tid", "tenant-a ", false)]
    public void should_validate_the_enabled_contract(bool hasHandler, string claimType, string mappedTenant, bool expected)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(hasHandler
            ? new Dictionary<string, string?> { [$"{C.Authentication.SectionKey}:JwtBearer:Authority"] = "https://issuer.example.test" }
            : []).Build();
        var options = new C.Authentication
        {
            ExternalTokenTenantBinding = new()
            {
                Require = true,
                TenantClaimType = claimType,
                TenantMapping = new Dictionary<string, string> { ["external-a"] = mappedTenant },
            },
        };
        new ExternalTokenTenantBindingConfigurationValidator(configuration).Validate(null, options).Succeeded.ShouldEqual(expected);
    }

    [Fact]
    public void should_not_validate_unused_binding_settings()
    {
        var options = new C.Authentication { ExternalTokenTenantBinding = new() { TenantClaimType = string.Empty } };
        var configuration = new ConfigurationBuilder().Build();
        new ExternalTokenTenantBindingConfigurationValidator(configuration).Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void should_leave_binding_disabled_by_default() =>
        new C.Authentication().ExternalTokenTenantBinding.Require.ShouldBeFalse();
}
