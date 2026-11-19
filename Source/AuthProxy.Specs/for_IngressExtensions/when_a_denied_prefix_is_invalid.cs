// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.for_IngressExtensions;

public class when_a_denied_prefix_is_invalid : Specification
{
    WebApplicationBuilder _builder;
    Exception? _exception;

    void Establish()
    {
        _builder = WebApplication.CreateBuilder();
        _builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.Ingress.SectionKey}:DeniedPathPrefixes:0"] = "/%69nternal",
        });
    }

    async Task Because()
    {
        await using var app = _builder.AddIngressConfiguration().Build();
        _exception = await Catch.Exception(() => app.StartAsync());
    }

    [Fact] void should_fail_startup() => _exception.ShouldBeOfExactType<OptionsValidationException>();
}
