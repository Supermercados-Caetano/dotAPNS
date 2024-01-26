using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace dotAPNS.AspNetCore
{
	using Microsoft.Extensions.Logging;
#if NET6_0_OR_GREATER
	using System.Threading.Channels;
	using System.Threading.Tasks.Dataflow;
#endif
	public interface IApnsService
	{
		Task<ApnsResponse> SendPush(ApplePush push, X509Certificate2 cert, bool useSandbox = false, CancellationToken cancellationToken = default);
		Task<ApnsResponse> SendPush(ApplePush push, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
		Task<List<ApnsResponse>> SendPushes(IReadOnlyCollection<ApplePush> pushes, X509Certificate2 cert, bool useSandbox = false, CancellationToken cancellationToken = default);
		Task<List<ApnsResponse>> SendPushes(IReadOnlyCollection<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
		Task<IEnumerable<ApnsResponse>> SendPushesTasks(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
#if NET6_0_OR_GREATER
		Task<IEnumerable<ApnsResponse>> SendPushesParallel(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
		IAsyncEnumerable<ApnsResponse> SendPushesAsyncEnumerable(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
		IAsyncEnumerable<ApnsResponse> SendPushesWhenEach(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default);
#endif
	}

	public class ApnsService : IApnsService
	{
		readonly IApnsClientFactory _apnsClientFactory;
		readonly ILogger<ApnsService> logger;
		readonly ApnsServiceOptions _options;

		// TODO implement expiration policy
		readonly ConcurrentDictionary<string, IApnsClient> _cachedCertClients = new ConcurrentDictionary<string, IApnsClient>(); // key is cert thumbprint and sandbox prefix
		readonly ConcurrentDictionary<string, IApnsClient> _cachedJwtClients = new ConcurrentDictionary<string, IApnsClient>(); // key is bundle id and sandbox prefix

		public ApnsService(IApnsClientFactory apnsClientFactory, IOptions<ApnsServiceOptions> options, ILogger<ApnsService> logger)
		{
			_apnsClientFactory = apnsClientFactory;
			this.logger = logger;
			_options = options.Value;
		}

		public Task<ApnsResponse> SendPush(ApplePush push, X509Certificate2 cert, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + cert.Thumbprint;
			var client = _cachedCertClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingCert(cert, useSandbox, _options.DisableServerCertificateValidation));

			try
			{
				return client.SendAsync(push, cancellationToken);
			}
			catch
			{
				_cachedCertClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

		public Task<ApnsResponse> SendPush(ApplePush push, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			try
			{
				return client.SendAsync(push, cancellationToken);
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

		public async Task<List<ApnsResponse>> SendPushes(IReadOnlyCollection<ApplePush> pushes, X509Certificate2 cert, bool useSandbox = false, CancellationToken cancellationToken = default) //TODO implement concurrent sendings
		{
			if (string.IsNullOrWhiteSpace(cert.Thumbprint))
				throw new InvalidOperationException("Certificate does not have a thumbprint.");

			string clientCacheId = (useSandbox ? "s_" : "") + cert.Thumbprint;
			var client = _cachedCertClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingCert(cert, useSandbox, _options.DisableServerCertificateValidation));

			var result = new List<ApnsResponse>(pushes.Count);
			try
			{
				foreach (var push in pushes)
					result.Add(await client.SendAsync(push, cancellationToken));
				return result;
			}
			catch
			{
				_cachedCertClients.TryRemove(cert.Thumbprint, out _);
				throw;
			}
		}

		public async Task<List<ApnsResponse>> SendPushes(IReadOnlyCollection<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			var result = new List<ApnsResponse>(pushes.Count);
			try
			{
				foreach (var push in pushes)
					result.Add(await client.SendAsync(push, cancellationToken));
				return result;
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

		public async Task<IEnumerable<ApnsResponse>> SendPushesTasks(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			//var result = new List<ApnsResponse>(pushes.Count);
			try
			{
				//foreach (var push in pushes)
				//	result.Add(await client.SendAsync(push, cancellationToken));
				//return result;
				var ret = await Task.WhenAll(pushes.Select(push => client.SendAsync(push, cancellationToken))).ConfigureAwait(false);
				return ret;
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

#if NET6_0_OR_GREATER

		public async Task<IEnumerable<ApnsResponse>> SendPushesParallel(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			//var result = new List<ApnsResponse>(pushes.Count);
			var result = new ConcurrentBag<ApnsResponse>();
			try
			{
				//foreach (var push in pushes)
				//	result.Add(await client.SendAsync(push, cancellationToken));
				//return result;
				var opt = new ParallelOptions
				{
					CancellationToken = cancellationToken,
					MaxDegreeOfParallelism = 15,
				};

				await Parallel.ForEachAsync(pushes,
					opt,
					async (push, cts) =>
					{
						result.Add(await client.SendAsync(push, cts));
					}).ConfigureAwait(false);
				return result.AsEnumerable();
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}


		public IAsyncEnumerable<ApnsResponse> SendPushesAsyncEnumerable(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			var channel = Channel.CreateBounded<ApnsResponse>(new BoundedChannelOptions(15)
			{
				FullMode = BoundedChannelFullMode.Wait,
			});
			var writer = channel.Writer;
			var inputTasks = pushes.Select(push => client.SendAsync(push, cancellationToken));
			var continuations = inputTasks.Select(t => t.ContinueWith(async x =>
			{
				await writer.WaitToWriteAsync();
				await writer.WriteAsync(x.Result);
			}));
			try
			{
				_ = Task.WhenAll(continuations)
					.ContinueWith(t => writer.Complete(t.Exception));
				return channel.Reader.ReadAllAsync(cancellationToken);
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

		public IAsyncEnumerable<ApnsResponse> SendPushesWhenEach(IEnumerable<ApplePush> pushes, ApnsJwtOptions jwtOptions, bool useSandbox = false, CancellationToken cancellationToken = default)
		{
			string clientCacheId = (useSandbox ? "s_" : "") + jwtOptions.BundleId;
			var client = _cachedJwtClients.GetOrAdd(clientCacheId, _ =>
				_apnsClientFactory.CreateUsingJwt(jwtOptions, useSandbox, _options.DisableServerCertificateValidation));
			var inputTasks = pushes.Select(async push =>
			{
				try
				{
					return await client.SendAsync(push, cancellationToken);
				}
				catch (Exception ex)
				{
					logger.LogError(ex, null);
					throw;
				}
			});
			try
			{
				return WhenEach<ApnsResponse>(inputTasks, cancellationToken);
			}
			catch
			{
				_cachedJwtClients.TryRemove(clientCacheId, out _);
				throw;
			}
		}

		public static IAsyncEnumerable<T> ToAsyncEnumerable<T>(IEnumerable<Task<T>> inputTasks)
		{
			var channel = Channel.CreateUnbounded<T>();
			var writer = channel.Writer;
			var continuations = inputTasks.Select(t => t.ContinueWith(x =>
												   writer.TryWrite(x.Result)));
			_ = Task.WhenAll(continuations)
					.ContinueWith(t => writer.Complete(t.Exception));

			return channel.Reader.ReadAllAsync();
		}

		public async static IAsyncEnumerable<TResult> WhenEach<TResult>(
	IEnumerable<Task<TResult>> tasks,
	[EnumeratorCancellation] CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(tasks);
			Channel<Task<TResult>> channel = Channel.CreateBounded<Task<TResult>>(new BoundedChannelOptions(15)
			{
				FullMode = BoundedChannelFullMode.Wait,
			});
			if (tasks.Count() == 0) channel.Writer.Complete();
			using CancellationTokenSource completionCts = new();
			List<Task> continuations = new(tasks.Count());
			try
			{
				int pendingCount = tasks.Count();
				foreach (Task<TResult> task in tasks)
				{
					if (task is null) throw new ArgumentException(
						$"The tasks argument included a null value.", nameof(tasks));
					continuations.Add(task.ContinueWith(t =>
					{
						bool accepted = channel.Writer.TryWrite(t);
						Debug.Assert(accepted);
						if (Interlocked.Decrement(ref pendingCount) == 0)
							channel.Writer.Complete();
					}, completionCts.Token, TaskContinuationOptions.ExecuteSynchronously |
						TaskContinuationOptions.DenyChildAttach, TaskScheduler.Default));
				}

				await foreach (Task<TResult> task in channel.Reader
					.ReadAllAsync(cancellationToken).ConfigureAwait(false))
				{
					yield return await task.ConfigureAwait(false);
					cancellationToken.ThrowIfCancellationRequested();
				}
			}
			finally
			{
				completionCts.Cancel();
				try { await Task.WhenAll(continuations).ConfigureAwait(false); }
				catch (OperationCanceledException) { } // Ignore
			}
		}

		public static async Task AsyncParallelForEach<T>(IAsyncEnumerable<T> source, Func<T, Task> body, int maxDegreeOfParallelism = DataflowBlockOptions.Unbounded, TaskScheduler scheduler = null)
		{
			var options = new ExecutionDataflowBlockOptions
			{
				MaxDegreeOfParallelism = maxDegreeOfParallelism
			};
			if (scheduler != null)
				options.TaskScheduler = scheduler;

			var block = new ActionBlock<T>(body, options);

			await foreach (var item in source)
				block.Post(item);

			block.Complete();
			await block.Completion;
		}

#endif
	}
}
