// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.for_IngressExtensions.given;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_TenantConfigurationValidator;

public class when_startup_validation_finds_a_whitespace_source_identifier : an_ingress_configuration
{
    Exception? _exception;

    protected override IDictionary<string, string?> IngressSettings => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Tenants:tenant-one:SourceIdentifiers:0"] = " "
    };

    async Task Because() => _exception = await Record.ExceptionAsync(
        async () => await _serviceProvider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(CancellationToken.None));

    [Fact] void should_reject_startup() => _exception.ShouldBeOfExactType<OptionsValidationException>();
    [Fact] void should_name_the_tenant_and_list() =>
        _exception!.Message.ShouldContain($"{C.AuthProxy.SectionKey}:Tenants:tenant-one:SourceIdentifiers");
}
