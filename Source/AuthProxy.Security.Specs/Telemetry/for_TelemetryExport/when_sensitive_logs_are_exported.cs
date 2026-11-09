// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.Tenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.Telemetry.for_TelemetryExport;

public class when_sensitive_logs_are_exported : given.an_export_pipeline
{
    void Because()
    {
        var factory = Application.Services.GetRequiredService<ILoggerFactory>();
        var verifier = factory.CreateLogger<TenantVerifier>();
        verifier.TenantNotFound(SensitiveValue);
        verifier.TenantVerificationFailed(SensitiveValue, 503);
        verifier.TenantVerificationError(new HttpRequestException(SensitiveUrl), SensitiveValue);
        var bearer = factory.CreateLogger("Cratis.AuthProxy.BearerRoutes");
        bearer.BearerTenantNotVerified(SensitiveValue, SensitiveUrl);
        var identity = factory.CreateLogger("Cratis.AuthProxy.Identity");
        identity.CallingIdentityEndpoint(SensitiveUrl, "backend");
    }

    [Fact] public void should_export_all_five_logs_including_debug() => Assert.Equal(5, Logs.Count);
    [Fact] public void should_not_export_tenant_ids_in_any_record_field() => Assert.DoesNotContain(Logs, log => log.Contains(SensitiveValue, StringComparison.Ordinal));
    [Fact] public void should_not_export_debug_urls_or_exception_urls() => Assert.DoesNotContain(Logs, log => log.Contains("private-code", StringComparison.Ordinal));
    [Fact] public void should_export_bounded_messages() => Assert.All(Logs, log => Assert.Contains("Log details redacted", log, StringComparison.Ordinal));
}
