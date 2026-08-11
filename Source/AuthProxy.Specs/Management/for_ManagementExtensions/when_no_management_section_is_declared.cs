// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Management.for_ManagementExtensions;

/// <summary>
/// The deployment that never asked. Nothing is added, nothing is re-declared, and no second socket will be
/// opened — the process binds exactly what it bound before this feature existed.
/// </summary>
public class when_no_management_section_is_declared : given.a_deployment_serving_traffic
{
    ServiceProvider _services;

    void Because()
    {
        _builder.AddManagement();
        _services = Services();
    }

    [Fact] void should_leave_the_declared_addresses_alone() => DeclaredAddresses.ShouldContainOnly([PublicUrl]);
    [Fact] void should_not_register_a_readiness_check() => _builder.Services.ShouldNotContain(_ => _.ServiceType == typeof(IReadinessCheck));

    /// <summary>
    /// The validator is still registered, because a deployment that declares a broken section has to be
    /// refused — and whether the section is broken is not something a registration-time branch can decide
    /// as reliably as the validator does.
    /// </summary>
    [Fact] void should_still_judge_the_configuration() => _services.GetServices<IValidateOptions<C.AuthProxy>>().ShouldContain(_ => _ is ManagementConfigurationValidator);

    void Destroy() => _services.Dispose();
}
