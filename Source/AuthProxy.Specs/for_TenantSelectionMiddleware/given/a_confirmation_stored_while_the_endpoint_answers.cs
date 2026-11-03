// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

/// <summary>
/// A first request is held inside the tenant endpoint while a second request for the same account and
/// tenant is confirmed and stores its confirmation; the first request then receives the answer the
/// specification configures through _lateStatus, _lateBody and _lateFailure.
/// </summary>
public class a_confirmation_stored_while_the_endpoint_answers : a_tenant_selection_endpoint
{
    protected HttpStatusCode? _lateStatus;
    protected string _lateBody = "[]";
    protected Exception _lateFailure = new HttpRequestException("Tenant endpoint is unavailable");
    protected DefaultHttpContext _first;
    protected DefaultHttpContext _second;
    protected DefaultHttpContext _third;
    protected DefaultHttpContext _probe;
    protected int _callsBeforeProbe;
    protected int _callsAfterProbe;
    protected int _callsBeforeThird;
    protected bool _nextCalledForThird;
    TaskCompletionSource _firstEntered;
    TaskCompletionSource _releaseFirst;

    void Establish()
    {
        _firstEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _releaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
        given.signed_selected_tenant_cookies.Seed(_context, "tenant-a");
        _beforeEndpointAnswers = async call =>
        {
            if (call == 1)
            {
                _firstEntered.SetResult();
                await _releaseFirst.Task;
            }
        };
    }

    protected async Task RunInterleavedRequests()
    {
        _first = NewRequest();
        _endpointStatus = HttpStatusCode.OK;
        _endpointBody = Tenants2;
        var first = _middleware.InvokeAsync(_first);
        await _firstEntered.Task;

        _second = NewRequest();
        await _middleware.InvokeAsync(_second);

        _callsBeforeProbe = _endpointCalls;
        _probe = NewRequest();
        await _middleware.InvokeAsync(_probe);
        _callsAfterProbe = _endpointCalls;

        _endpointStatus = _lateStatus;
        _endpointBody = _lateBody;
        _endpointFailure = _lateFailure;
        _releaseFirst.SetResult();
        await first;

        _callsBeforeThird = _endpointCalls;
        _nextCalled = false;
        _third = NewRequest();
        await _middleware.InvokeAsync(_third);
        _nextCalledForThird = _nextCalled;
    }

    protected static string Confirmed(HttpContext context) =>
        context.Items.TryGetValue(SelectionSourceIdentifierStrategy.ConfirmedTenantItemKey, out var confirmed) ? confirmed as string ?? string.Empty : string.Empty;

    DefaultHttpContext NewRequest()
    {
        var request = new DefaultHttpContext { User = _context.User };
        request.Request.Path = "/products";
        request.Request.Headers["Sec-Fetch-Dest"] = "document";
        request.Request.Headers.Cookie = _context.Request.Headers.Cookie;
        request.Response.Body = new MemoryStream();
        return request;
    }
}
