// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.KeyRing;

public class when_a_key_ring_names_an_undefined_store : Specification
{
    ServiceProvider _serviceProvider;
    Exception? _exception;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:DataProtection:Store"] = "3",
        });
        builder.AddIngressConfiguration();
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    void Because() => _exception = Record.Exception(() => _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_store_setting() => _exception!.Message.ShouldContain("Cratis:AuthProxy:DataProtection:Store");
    [Fact] void should_name_the_unsupported_value() => _exception!.Message.ShouldContain("'3'");

    void Destroy() => _serviceProvider.Dispose();
}
