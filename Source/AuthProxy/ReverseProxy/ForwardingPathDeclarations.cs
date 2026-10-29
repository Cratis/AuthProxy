// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.ReverseProxy;

/// <summary>Reports anonymous and bearer declarations that their service's forwarding policy refuses.</summary>
internal static class ForwardingPathDeclarations
{
    /// <summary>Warns about declarations refused by their service policy.</summary>
    /// <param name="serviceName">The configured service name.</param>
    /// <param name="service">The service configuration.</param>
    /// <param name="logger">The configuration logger.</param>
    internal static void Warn(string serviceName, C.Service service, ILogger logger)
    {
        if (!ForwardingPathPolicy.IsConfigured(service))
        {
            return;
        }
        var declarations = Anonymous(service).Concat(service.BearerRoutes.SelectMany(Bearer));
        foreach (var declaration in declarations.Where(declaration => IsRefused(service, declaration)))
        {
            logger.ForwardingPathConflict(serviceName, declaration.Kind, declaration.Path);
        }
    }

    static IEnumerable<Declaration> Anonymous(C.Service service) => service.AnonymousPaths
        .Where(path => AnonymousPaths.TryNormalize(path, out _))
        .Select(path => new Declaration("AnonymousPaths", path, ForwardingPathPolicy.EffectivePath(path, service.StripPathPrefix ? service.PathPrefix : null)));

    static IEnumerable<Declaration> Bearer(C.BearerRoute route)
    {
        yield return new("BearerRoutes", route.PathPrefix, route.PathPrefix);
        if (Uri.TryCreate(route.ResourceMetadataUrl, UriKind.Absolute, out var metadata))
        {
            yield return new("ResourceMetadataPath", metadata.AbsolutePath, metadata.AbsolutePath);
        }
    }

    static bool IsRefused(C.Service service, Declaration declaration)
    {
        var request = new DefaultHttpContext().Request;
        request.Path = declaration.Path;
        request.Method = HttpMethods.Get;
        return ForwardingPathPolicy.Evaluate(request, service, declaration.EffectivePath) != ForwardingPathRefusal.None;
    }

    sealed record Declaration(string Kind, string Path, PathString EffectivePath);
}
