// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact] void should_register_invite_token_validator() =>
        _serviceProvider.GetRequiredService<IInviteTokenValidator>().ShouldBeOfExactType<InviteTokenValidator>();
}
