// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Reactive.Subjects;
using Cratis.Arc.Commands.ModelBound;
using Cratis.Arc.Queries.ModelBound;

namespace ArcSample;

/// <summary>The payload AuthProxy posts to the verification endpoint.</summary>
/// <param name="Service">The service key.</param>
/// <param name="RoutePrefix">The route prefix the token is scoped to.</param>
/// <param name="ClientId">The client identifier.</param>
/// <param name="ClientSecret">The client secret.</param>
public record VerifyRequest(string Service, string RoutePrefix, string ClientId, string ClientSecret);

/// <summary>An observable read model that emits the current greeting at once and every later change.</summary>
/// <param name="Message">The message.</param>
[ReadModel]
public record Greeting(string Message)
{
    /// <summary>The state the <see cref="Greet"/> command changes.</summary>
    public static readonly BehaviorSubject<Greeting> Current = new(new("hello-through-authproxy"));

    /// <summary>Observes the greeting.</summary>
    /// <returns>A subject that has already emitted its current value.</returns>
    public static ISubject<Greeting> Observe() => Current;
}

/// <summary>A command with no events and no Chronicle: it changes the greeting the query observes.</summary>
/// <param name="Name">Who to greet.</param>
[Command]
public record Greet(string Name)
{
    /// <summary>Handles the command.</summary>
    /// <returns>The greeting.</returns>
    public string Handle()
    {
        var message = $"hello {Name}";
        Greeting.Current.OnNext(new(message));
        return message;
    }
}
