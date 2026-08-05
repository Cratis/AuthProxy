// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

/// <summary>
/// A resource the AuthProxy builders can be applied to, plus the means to read back what they wrote.
/// <para>
/// The builders express configuration as environment variables, which is how AuthProxy is configured in a
/// container. They are recorded as callbacks rather than values, so reading them back means running those
/// callbacks — that is what <see cref="EnvironmentVariables"/> does, and it is the only way to assert on
/// what a deployment would actually receive.
/// </para>
/// </summary>
public class an_auth_proxy_resource : Specification
{
    protected IDistributedApplicationBuilder _builder;
    protected IResourceBuilder<ContainerResource> _resource;

    void Establish()
    {
        _builder = DistributedApplication.CreateBuilder();
        _resource = _builder.AddContainer("auth-proxy", "cratis/authproxy");
    }

    /// <summary>
    /// Runs the resource's environment callbacks and returns what they produced.
    /// </summary>
    /// <returns>The environment variables the resource would be started with.</returns>
    protected async Task<Dictionary<string, string>> EnvironmentVariables()
    {
        var context = new EnvironmentCallbackContext(
            new DistributedApplicationExecutionContext(DistributedApplicationOperation.Run));

        foreach (var annotation in _resource.Resource.Annotations.OfType<EnvironmentCallbackAnnotation>())
        {
            await annotation.Callback(context);
        }

        return context.EnvironmentVariables.ToDictionary(_ => _.Key, _ => _.Value?.ToString() ?? string.Empty, StringComparer.Ordinal);
    }
}
