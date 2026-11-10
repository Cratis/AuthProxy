// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_TenantResolver.given;

namespace Cratis.AuthProxy.for_TenantResolver;

public class when_resolving_each_resolution_with_none_configured : a_tenant_resolver
{
    TenantResolutionResult[] _results;

    void Establish()
    {
        _context.Items[TenancyMiddleware.TenantVerificationUrlTemplateItemKey] = "https://stale.example.com/{tenant}";
        _resolver = CreateResolver(ConfigurationOf());
    }

    void Because() => _results = [.. _resolver.ResolveEach(_context)];

    [Fact] void should_return_no_results() => _results.ShouldBeEmpty();
    [Fact] void should_clear_the_verification_template() => _context.Items.ContainsKey(TenancyMiddleware.TenantVerificationUrlTemplateItemKey).ShouldBeFalse();
    [Fact] void should_not_log() => _logger.Messages.ShouldBeEmpty();
}
