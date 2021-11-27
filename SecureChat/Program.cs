using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.Extensions.DependencyInjection;
using SecureChat.Hubs;

namespace SecureChat {
    class Program {
        public static async Task Main(string[] args) {
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
                    var keyExchangeTask = new TaskCompletionSource();
                    await using var connection = new HubConnectionBuilder()
                                                 .WithUrl($"{userAddress}/chat")
                                                 .Build();
                    var des = DES.Create();

                    void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e) {
                        des.Dispose();
                        connection.DisposeAsync().AsTask().Wait();
                        Process.GetCurrentProcess().Kill();
                    }

                    Console.CancelKeyPress += OnCancelKeyPress;

                    connection.On<byte[]>("SendPublicKey",
                                          async publicKey => {
                                              using var rsa = RSA.Create();
                                              rsa.ImportRSAPublicKey(publicKey, out _);
                                              var encryptedKey = rsa.Encrypt(des.Key, RSAEncryptionPadding.Pkcs1);
                                              Console.WriteLine("Sending DES encrypted private key");
                                              await connection.InvokeAsync("SendSymmetricKey", encryptedKey);
                                              keyExchangeTask.SetResult();
                                          });

                    connection.On<byte[]>("SendMessage",
                                          encryptedMessage => {
                                              var messageBytes = des.DecryptEcb(encryptedMessage, PaddingMode.None);
                                              var message      = Encoding.Default.GetString(messageBytes);
                                              Console.Write("\nMessage received: ");
                                              Console.WriteLine(message);
                                              Console.Write("Input message: ");
                                          });

                    connection.Closed += _ => {
                        Console.WriteLine("\nClient disconnected");
                        OnCancelKeyPress(null, null!);
                        return Task.CompletedTask;
                    };

                    await connection.StartAsync();
                    await keyExchangeTask.Task;
                    while (true) {
                        Console.Write("Input message: ");
                        var message          = Console.ReadLine()!;
                        var encryptedMessage = des.EncryptEcb(Encoding.Default.GetBytes(message), PaddingMode.Zeros);
                        await connection.InvokeAsync("SendMessage", encryptedMessage);
                    }
                } catch (Exception) {
                    // ignored
                }
            }
        }
    }
}
