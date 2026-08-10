// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.for_TenancyMiddleware.when_logging_a_missing_tenant;

/// <summary>
/// Tenant verification runs on every request, so it also runs on an invitation request whose path is a live
/// bearer capability. Which tenant could not be found is the diagnostic; the URL that carries the invitation
/// is not.
/// </summary>
public class on_a_capability_path : Specification
{
    const string TenantId = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
    const string SensitiveCapability = "sensitive-capability-value";

    readonly RecordingLogger<TenancyMiddleware> _logger = new();

    TenancyMiddleware _middleware;
    DefaultHttpContext _context;

    void Establish()
    {
        var optionsMonitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        optionsMonitor.CurrentValue.Returns(new C.AuthProxy());

        var tenantResolver = Substitute.For<ITenantResolver>();
        tenantResolver
            .TryResolve(Arg.Any<HttpContext>(), out Arg.Any<string>())
            .Returns(call =>
            {
                call[1] = TenantId;
                return true;
            });

        var tenantVerifier = Substitute.For<ITenantVerifier>();
        tenantVerifier.VerifyAsync(TenantId).Returns(Task.FromResult(false));

        _middleware = new TenancyMiddleware(
            _ => Task.CompletedTask,
            optionsMonitor,
            tenantResolver,
            tenantVerifier,
            Substitute.For<IErrorPageProvider>(),
            _logger);

        _context = new DefaultHttpContext();
        _context.Request.Path = $"{WellKnownPaths.InvitePathPrefix}/{SensitiveCapability}";
    }

    async Task Because() => await _middleware.InvokeAsync(_context);

    [Fact] void should_not_disclose_the_capability() => _logger.Text.ShouldNotContain(SensitiveCapability);
    [Fact] void should_still_record_the_bounded_reason() => _logger.Text.ShouldContain(TenantId);
    [Fact] void should_record_the_redacted_route() => _logger.Text.ShouldContain($"{WellKnownPaths.InvitePathPrefix}/[redacted]");
}
