// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ReverseProxy.for_ProxyOwnedCookiesTransform.given;

/// <summary>
/// A request on its way to a service, carrying the given cookies, run through the transform.
/// </summary>
public class a_proxied_request : Specification
{
    protected string? _sessionCookieName;
    protected string[] _cookies = [];
    protected Dictionary<string, C.Service> _services = [];
    protected RequestTransformContext _transformContext;

    protected string? Forwarded => _transformContext.ProxyRequest.Headers.TryGetValues("Cookie", out var values) ? string.Join(" | ", values) : null;

    protected async Task Apply()
    {
        var options = new C.AuthProxy { Session = new C.Session { CookieName = _sessionCookieName }, Services = _services };
        var monitor = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        monitor.CurrentValue.Returns(options);
        var services = new ServiceCollection().AddSingleton(monitor).BuildServiceProvider();

        _transformContext = new RequestTransformContext
        {
            HttpContext = new DefaultHttpContext { RequestServices = services },
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, (Uri?)null),
            Path = "/orders"
        };

        if (_cookies.Length > 0)
        {
            _transformContext.ProxyRequest.Headers.TryAddWithoutValidation("Cookie", _cookies);
        }

        await new ProxyOwnedCookiesTransform().ApplyAsync(_transformContext);
    }
}
