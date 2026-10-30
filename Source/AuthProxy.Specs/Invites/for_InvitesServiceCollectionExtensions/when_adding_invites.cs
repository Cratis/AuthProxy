// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Invites.for_InvitesServiceCollectionExtensions;

public class when_adding_invites : Specification
{
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddInvites();
        builder.Services.AddDataProtection();
        builder.Services.AddSingleton(Substitute.For<ICanonicalIdentityResolver>());
        builder.Services.AddSingleton(Substitute.For<ITenantResolver>());
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact]
    void should_register_invitation_token_keys() =>
        _serviceProvider.GetRequiredService<IInvitationTokenKeys>().ShouldBeOfExactType<InvitationTokenKeys>();

    [Fact]
    void should_limit_the_metadata_timeout() =>
        _serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient(InvitationTokenKeys.HttpClientName).Timeout.ShouldEqual(InvitationTokenKeys.FetchTimeout);

    [Fact]
    void should_limit_the_metadata_response_buffer() =>
        _serviceProvider.GetRequiredService<IHttpClientFactory>().CreateClient(InvitationTokenKeys.HttpClientName).MaxResponseContentBufferSize.ShouldEqual(InvitationTokenKeys.MaximumResponseSize);

    [Fact] void should_register_one_invitation_lifecycle() => _serviceProvider.GetRequiredService<InvitationLifecycle>().ShouldEqual(_serviceProvider.GetRequiredService<InvitationLifecycle>());

    [Fact]
    void should_register_invite_token_validator() =>
        _serviceProvider.GetRequiredService<IInviteTokenValidator>().ShouldBeOfExactType<InviteTokenValidator>();
}
