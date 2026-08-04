// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.SignIns.for_SignInsServiceCollectionExtensions;

public class when_adding_sign_ins : Specification
{
    ServiceProvider _serviceProvider;

    void Establish()
    {
        var builder = WebApplication.CreateBuilder();

        // The notifier depends on the shared HTTP client factory, registered by the ingress configuration in
        // the real host; the spec adds it directly so the notifier can be constructed in isolation.
        builder.Services.AddHttpClient();
        builder.AddSignIns();
        _serviceProvider = builder.Services.BuildServiceProvider();
    }

    [Fact] void should_register_the_sign_in_notifier() =>
        _serviceProvider.GetRequiredService<ISignInNotifier>().ShouldBeOfExactType<SignInNotifier>();

    [Fact] void should_register_the_client_location_resolver() =>
        _serviceProvider.GetRequiredService<IClientLocationResolver>().ShouldBeOfExactType<ClientLocationResolver>();
}
