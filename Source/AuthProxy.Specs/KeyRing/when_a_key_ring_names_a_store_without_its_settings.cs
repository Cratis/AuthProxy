// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.KeyRing;

/// <summary>
/// Asserted through the real registration rather than on the validator alone, because a validator nothing
/// registers is a validator that never runs.
/// </summary>
public class when_a_key_ring_names_a_store_without_its_settings : Specification
{
    ServiceProvider _serviceProvider;
    Exception? _exception;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:DataProtection:Store"] = "Redis",
        });
        builder.AddIngressConfiguration();
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    void Because() => _exception = Record.Exception(() => _serviceProvider.GetRequiredService<IOptions<C.AuthProxy>>().Value);

    [Fact] void should_refuse_the_configuration() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_missing_setting() => _exception!.Message.ShouldContain("DataProtection:Redis:ConnectionString");

    void Destroy() => _serviceProvider.Dispose();
}
