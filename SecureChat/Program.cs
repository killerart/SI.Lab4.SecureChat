using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using SecureChat.Hubs;

namespace SecureChat {
    class Program {
        private static DES                     _des;
        private static CancellationTokenSource _tokenSource;
        private static HubConnection           _connection;
        private static TaskCompletionSource    _keyExchangeTask;

        public static async Task Main(string[] args) {
            Console.CancelKeyPress += OnConsoleCancelKeyPress;

            Console.WriteLine("Input user address to connect to him or the word 'wait' to wait for connections:");
            var userAddress = Console.ReadLine()!;
            if (userAddress.Equals("wait", StringComparison.OrdinalIgnoreCase)) {
                var builder = WebApplication.CreateBuilder(args);
                builder.Services.AddSignalR();
                var app = builder.Build();
                app.MapHub<ChatHub>("/chat");
                await app.RunAsync();
            } else {
                try {
                    _tokenSource     = new CancellationTokenSource();
                    _keyExchangeTask = new TaskCompletionSource();
                    _connection = new HubConnectionBuilder()
                                  .WithUrl($"{userAddress}/chat")
                                  .Build();
                    _des = DES.Create();

                    _connection.On<byte[]>("SendPublicKey", SendPublicKey);

                    _connection.Closed += _ => {
                        Console.WriteLine("\nClient disconnected");
                        if (_tokenSource is not null)
                            _tokenSource.Cancel();
                        return Task.CompletedTask;
                    };

                    await _connection.StartAsync(_tokenSource.Token);
                    await _keyExchangeTask.Task;

                    await _connection.SendAsync("SendMessages", SendMessagesStream(_tokenSource.Token));
                    var messageStream = _connection.StreamAsync<byte[]>("ReceiveMessages", _tokenSource.Token);

                    try {
                        await foreach (var encryptedMessage in messageStream.WithCancellation(_tokenSource.Token)) {
                            DecryptMessage(encryptedMessage);
                        }
                    } catch (Exception) {
                        // ignored
                    }
                } catch (Exception) {
                    // ignored
                } finally {
                    _tokenSource = null;
                    _des?.Dispose();
                }
            }
        }

        private static void DecryptMessage(byte[] encryptedMessage) {
            var messageBytes = _des.DecryptEcb(encryptedMessage, PaddingMode.None);
            var message      = Encoding.Default.GetString(messageBytes);
            Console.Write("\nMessage received: ");
            Console.WriteLine(message);
            Console.Write("Input message: ");
        }

        private static async IAsyncEnumerable<byte[]> SendMessagesStream([EnumeratorCancellation] CancellationToken ct) {
            yield return null;
            while (!ct.IsCancellationRequested) {
                Console.Write("Input message: ");
                var message          = Console.ReadLine()!;
                var encryptedMessage = _des.EncryptEcb(Encoding.Default.GetBytes(message), PaddingMode.Zeros);
                yield return encryptedMessage;
            }
        }

        private static async Task SendPublicKey(byte[] publicKey) {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out _);
            var encryptedKey = rsa.Encrypt(_des.Key, RSAEncryptionPadding.Pkcs1);
            Console.WriteLine("Sending DES encrypted private key");
            await _connection.InvokeAsync("SendSymmetricKey", encryptedKey, _tokenSource.Token);
            _keyExchangeTask.SetResult();
        }

        private static void OnConsoleCancelKeyPress(object? o, ConsoleCancelEventArgs consoleCancelEventArgs) {
            if (_tokenSource is null)
                return;
            _tokenSource.Cancel();
            _tokenSource.Dispose();
        }
    }
}
