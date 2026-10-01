// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache;

public class when_reusing_records_issued_before_required_verification : Specification
{
    readonly List<bool> _requiredResults = [];
    readonly List<bool> _bestEffortResults = [];

    void Because()
    {
        var keys = new EphemeralDataProtectionProvider();
        var principal = new ClientPrincipal { UserId = "legacy-user" };
        IdentityAccountBinding.TryCreate(principal, out var account);
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds();
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        var service = new C.Service { Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" } };
        configuration.CurrentValue.Returns(new C.AuthProxy { Services = new Dictionary<string, C.Service> { ["main"] = service } });
        var cache = new IdentityAuthorizationCache(keys, configuration, Substitute.For<ILogger<IdentityAuthorizationCache>>());
        var records = new[]
        {
            keys.CreateProtector("Cratis.AuthProxy.Identity.Authorization.v1").Protect($"{expiresAt.ToString(CultureInfo.InvariantCulture)}|legacy-user|tenant-a"),

            // The old structured payload has no evidence that Required verification succeeded.
            keys.CreateProtector("Cratis.AuthProxy.Identity.Authorization.v2").Protect(JsonSerializer.Serialize(new
            {
                Version = 2,
                ExpiresAt = expiresAt,
                TenantId = "tenant-a",
                Account = account
            }))
        };

        foreach (var record in records)
        {
            var context = new DefaultHttpContext();
            context.Request.Headers.Cookie = $"{Cookies.IdentityAuthorization}={record}";
            service.IdentityVerification = C.IdentityVerificationMode.Required;
            _requiredResults.Add(cache.IsAuthorized(context, principal, "tenant-a"));
            service.IdentityVerification = C.IdentityVerificationMode.BestEffort;
            _bestEffortResults.Add(cache.IsAuthorized(context, principal, "tenant-a"));
        }
    }

    [Fact] void should_reject_both_old_formats_when_verification_is_required() => _requiredResults.ShouldContainOnly([false, false]);
    [Fact] void should_preserve_reuse_for_explicit_best_effort() => _bestEffortResults.ShouldContainOnly([true, true]);
}
