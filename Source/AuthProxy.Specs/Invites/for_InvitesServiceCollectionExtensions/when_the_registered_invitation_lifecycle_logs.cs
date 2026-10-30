// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.given;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Invites.for_InvitesServiceCollectionExtensions;

/// <summary>
/// The registered lifecycle keeps logging under the middleware category, while the registered completion keeps
/// logging under its own.
/// </summary>
public class when_the_registered_invitation_lifecycle_logs : Specification
{
    readonly RecordingLogger<InviteMiddleware> _middlewareLogger = new();
    readonly RecordingLogger<InviteCompletion> _completionLogger = new();
    InvitationLifecycle _lifecycle;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddInvites();
        builder.Services.AddDataProtection();
        builder.Services.AddSingleton(Substitute.For<ICanonicalIdentityResolver>());
        builder.Services.AddSingleton(Substitute.For<ITenantResolver>());
        builder.Services.AddSingleton<ILogger<InviteMiddleware>>(_middlewareLogger);
        builder.Services.AddSingleton<ILogger<InviteCompletion>>(_completionLogger);
        _lifecycle = builder.Services.BuildServiceProvider().GetRequiredService<InvitationLifecycle>();
    }

    async Task Because() => await _lifecycle.Exchange(new DefaultHttpContext(), "token");

    [Fact] void should_log_under_the_invite_middleware_category() => _middlewareLogger.Text.ShouldContain("Invite exchange URL is not configured");
    [Fact] void should_not_log_under_the_invite_completion_category() => _completionLogger.Messages.ShouldBeEmpty();
}
