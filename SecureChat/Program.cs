using System;
using System.IO;
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
        public static readonly CancellationTokenSource TokenSource = new();

        public static async Task Main(string[] args) {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddSignalR();
            var app = builder.Build();
            app.MapHub<ChatHub>("/chat");
            var appTask = app.RunAsync();

            try {
                Console.Write("Input user address: ");
                await using var inputStream = Console.OpenStandardInput();
                using var       reader      = new StreamReader(inputStream);
                var             userAddress = await reader.ReadLineAsync().WaitAsync(TokenSource.Token);
                var connection = new HubConnectionBuilder()
                                 .WithUrl($"{userAddress!}/chat")
                                 .Build();
                var des = DES.Create();

                connection.On<byte[]>("SendPublicKey",
                                      async publicKey => {
                                          using var rsa = RSA.Create();
                                          rsa.ImportRSAPublicKey(publicKey, out _);
                                          var encryptedKey = rsa.Encrypt(des.Key, RSAEncryptionPadding.Pkcs1);
                                          Console.WriteLine("Sending DES encrypted private key");
                                          await connection.InvokeAsync("SendSymmetricKey", encryptedKey);
                                          Task.Run(async () => {
                                              while (true) {
                                                  Console.Write("Input message: ");
                                                  var message          = Console.ReadLine()!;
                                                  var encryptedMessage = des.EncryptEcb(Encoding.Default.GetBytes(message), PaddingMode.Zeros);
                                                  await connection.InvokeAsync("SendMessage", encryptedMessage);
                                              }
                                          });
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
                    des.Dispose();
                    return Task.CompletedTask;
                };

                await connection.StartAsync();
            } catch (Exception) {
                // ignored
            }

            await appTask;
        }
    }
}
