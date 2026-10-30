// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Http.Features;

namespace Cratis.AuthProxy.for_SetCookieSizeMiddleware.given;

public class a_set_cookie_size_middleware : Specification
{
    protected CapturingLogger _logger;
    protected SetCookieSizeMiddleware _middleware;
    protected DefaultHttpContext _context;
    protected IList<string> _setCookies = [];

    void Establish()
    {
        _logger = new CapturingLogger();
        _context = new DefaultHttpContext();
        _context.Request.Path = "/signin-google";
        _context.Features.Set<IHttpResponseFeature>(new StartingResponseFeature());
        _middleware = new SetCookieSizeMiddleware(
            ctx =>
            {
                foreach (var cookie in _setCookies)
                {
                    ctx.Response.Headers.Append("Set-Cookie", cookie);
                }

                return ((StartingResponseFeature)ctx.Features.Get<IHttpResponseFeature>()!).Start();
            },
            _logger);
    }

    protected int WarningsLogged => _logger.Messages.Count;

    protected string LoggedMessage => _logger.Messages.Single();

    /// <summary>
    /// Captures each message as it is logged, because the generated logging reuses its state object once Log returns.
    /// </summary>
    protected class CapturingLogger : ILogger<SetCookieSizeMiddleware>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception));
    }

    class StartingResponseFeature : HttpResponseFeature
    {
        readonly List<(Func<object, Task> Callback, object State)> _starting = [];

        public override void OnStarting(Func<object, Task> callback, object state) => _starting.Add((callback, state));

        public async Task Start()
        {
            foreach (var (callback, state) in _starting)
            {
                await callback(state);
            }
        }
    }
}
