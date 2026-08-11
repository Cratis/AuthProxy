// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_recording_with_verification_required.given;

/// <summary>
/// Provides an authorization cache for a deployment whose one service answers <c>/.cratis/me</c> with an
/// authorization verdict, with the re-validation interval left for each spec to state.
/// </summary>
public class a_verifying_deployment : Specification
{
    protected const string TenantId = "tenant-a";

    protected C.AuthProxy _configuration;
    protected IdentityAuthorizationCache _cache;
    protected DefaultHttpContext _context;

    void Establish()
    {
        _configuration = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" },
                    IdentityVerification = C.IdentityVerificationMode.Required
                }
            }
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(_ => _configuration);
        _cache = new IdentityAuthorizationCache(
            new EphemeralDataProtectionProvider(),
            options,
            Substitute.For<ILogger<IdentityAuthorizationCache>>());
        _context = new DefaultHttpContext();
    }

    /// <summary>
    /// Gets whether a sealed authorization record was written to the response.
    /// </summary>
    /// <returns><see langword="true"/> when a record was written; otherwise <see langword="false"/>.</returns>
    protected bool RecordWasWritten() =>
        _context.Response.Headers.SetCookie.Any(_ => _!.StartsWith($"{Cookies.IdentityAuthorization}=", StringComparison.Ordinal));
}
