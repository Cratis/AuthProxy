// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_activating_through_the_pipeline.given;

/// <summary>
/// Builds a container with the invitation services and runs a request through a pipeline that registers
/// <see cref="InviteMiddleware"/> the way a host would.
/// </summary>
public class an_invites_container : Specification
{
    protected IServiceCollection _services;
    protected bool _reachedNext;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();
        builder.AddInvites();
        _services = builder.Services;
        _services.AddDataProtection();
        _services.AddSingleton(Substitute.For<ITenantResolver>());
        _services.AddSingleton(Substitute.For<IErrorPageProvider>());
    }

    protected void AddCanonicalIdentityResolver() => _services.AddSingleton(Substitute.For<ICanonicalIdentityResolver>());

    protected async Task RunPipeline(Action<IApplicationBuilder> registerMiddleware)
    {
        var provider = _services.BuildServiceProvider();
        var application = new ApplicationBuilder(provider);
        registerMiddleware(application);
        application.Run(_ =>
        {
            _reachedNext = true;
            return Task.CompletedTask;
        });

        var context = new DefaultHttpContext();
        context.Request.Path = "/somewhere";
        context.RequestServices = provider;
        await application.Build()(context);
    }
}
