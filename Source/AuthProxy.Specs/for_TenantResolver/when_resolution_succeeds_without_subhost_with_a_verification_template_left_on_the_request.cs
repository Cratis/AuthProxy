// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_resolution_succeeds_without_subhost_with_a_verification_template_left_on_the_request : a_tenant_resolver
{
    void Establish()
    {
        _context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = "https://stale.example.com/{tenant}";
        _resolver = CreateResolver(
            ConfigurationOf(Resolution(C.TenantSourceIdentifierResolverType.Specified, new SpecifiedOptions { TenantId = "tenant-one" })),
            new SpecifiedSourceIdentifierStrategy());
    }

    void Because() => _succeeded = _resolver.TryResolve(_context, out _result);

    [Fact] void should_resolve() => _succeeded.ShouldBeTrue();
    [Fact] void should_not_report_a_parent_host() => _result.SubHostParentHost.ShouldBeNull();
    [Fact] void should_clear_the_verification_template() => _context.Items.ContainsKey(TenancyMiddleware.TenantVerificationUrlTemplateItemKey).ShouldBeFalse();
}
