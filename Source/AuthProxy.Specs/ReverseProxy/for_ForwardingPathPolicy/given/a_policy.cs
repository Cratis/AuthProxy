// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathPolicy.given;

public class a_policy : Specification
{
    protected C.Service _service = new();

    protected ForwardingPathRefusal Evaluate(string path, string method = "GET", string? header = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Method = method;
        if (header is not null)
        {
            context.Request.Headers[header] = "DELETE";
        }
        return ForwardingPathPolicy.Evaluate(context.Request, _service, context.Request.Path);
    }
}
