// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

public class an_auth_proxy_being_published : Specification
{
    protected const string SignerPrefix = "Cratis__AuthProxy__Services__main__ForwardedIdentity";
    protected const string VerifierPrefix = "Cratis__Arc__ForwardedIdentity";
    protected IDistributedApplicationBuilder _builder;
    protected IResourceBuilder<ContainerResource> _resource;
    protected IResourceBuilder<ContainerResource> _api;

    void Establish()
    {
        _builder = DistributedApplication.CreateBuilder(["--operation", "publish"]);
        _resource = _builder.AddContainer("auth-proxy", "cratis/authproxy");
        _api = _builder.AddContainer("api", "example/api");
    }

    protected static async Task<Dictionary<string, object>> RawEnvironmentOf(IResource resource)
    {
        var context = new EnvironmentCallbackContext(new DistributedApplicationExecutionContext(DistributedApplicationOperation.Publish));
        foreach (var annotation in resource.Annotations.OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(context);
        }
        return context.EnvironmentVariables;
    }
}
