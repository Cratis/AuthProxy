// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

public class when_search_index_exclusion_is_not_configured : given.an_ingress_configuration
{
    bool _excluded;

    void Because() => _excluded = _serviceProvider.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue.SearchIndexing.Exclude;

    [Fact] void should_keep_the_existing_behavior() => _excluded.ShouldBeFalse();
}
