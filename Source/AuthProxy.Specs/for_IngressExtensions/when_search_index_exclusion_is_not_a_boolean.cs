// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_IngressExtensions;

public class when_search_index_exclusion_is_not_a_boolean : given.an_ingress_configuration
{
    Exception _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:SearchIndexing:Exclude"] = "not-a-boolean"
    };

    void Because() => _exception = Catch.Exception(() => _ = _serviceProvider.GetRequiredService<IOptionsMonitor<C.AuthProxy>>().CurrentValue);

    [Fact] void should_refuse_the_invalid_configuration() => _exception.ShouldBeOfExactType<InvalidOperationException>();
}
