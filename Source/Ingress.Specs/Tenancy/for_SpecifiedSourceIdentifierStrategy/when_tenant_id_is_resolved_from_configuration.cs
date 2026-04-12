// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.Ingress.Tenancy.for_SpecifiedSourceIdentifierStrategy;

public class when_tenant_id_is_resolved_from_configuration : Specification
{
    SpecifiedSourceIdentifierStrategy _strategy;
    DefaultHttpContext _context;
    JsonObject _options;
    bool _succeeded;
    string _sourceIdentifier;

    void Establish()
    {
        _strategy = new SpecifiedSourceIdentifierStrategy();
        _options = new JsonObject();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Ingress:TenantResolutions:0:Strategy"] = "Specified",
                ["Ingress:TenantResolutions:0:Options:TenantId"] = "22222222-2222-2222-2222-222222222222"
            })
            .Build();

        _context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton<IConfiguration>(configuration)
                .BuildServiceProvider()
        };
    }

    void Because() => _succeeded = _strategy.TryResolveSourceIdentifier(_context, _options, out _sourceIdentifier);

    [Fact] void should_succeed() => _succeeded.ShouldBeTrue();
    [Fact] void should_return_the_configured_tenant_id() => _sourceIdentifier.ShouldEqual("22222222-2222-2222-2222-222222222222");
}