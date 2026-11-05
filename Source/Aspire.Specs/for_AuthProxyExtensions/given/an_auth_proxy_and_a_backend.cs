// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

public class an_auth_proxy_and_a_backend : an_auth_proxy_resource
{
    protected const string SignerPrefix = "Cratis__AuthProxy__Services__main__ForwardedIdentity";
    protected const string VerifierPrefix = "Cratis__Arc__ForwardedIdentity";
    protected IResourceBuilder<ContainerResource> _api;

    void Establish() => _api = _builder.AddContainer("api", "example/api");

    protected static async Task<Dictionary<string, object>> RawEnvironmentOf(IResource resource)
    {
        var context = new EnvironmentCallbackContext(new DistributedApplicationExecutionContext(DistributedApplicationOperation.Run));
        foreach (var annotation in resource.Annotations.OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(context);
        }
        return context.EnvironmentVariables;
    }

    protected static async Task<Dictionary<string, string>> EnvironmentOf(IResource resource)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (name, value) in await RawEnvironmentOf(resource))
        {
            values[name] = value is ParameterResource parameter ? (await parameter.GetValueAsync(default))! : value.ToString() ?? string.Empty;
        }
        return values;
    }
}
