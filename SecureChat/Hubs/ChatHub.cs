using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;

namespace SecureChat.Hubs {
    public class ChatHub : Hub<IChatClient> {
        public override async Task OnConnectedAsync() {
            var rsa = RSA.Create();
            SetRsa(rsa);
            var publicKey = rsa.ExportRSAPublicKey();

            Console.WriteLine("Sending RSA public key");
            await Clients.Caller.SendPublicKey(publicKey);
        }

        public void SendSymmetricKey(byte[] encryptedSymmetricKey) {
            var rsa          = GetRsa();
            var symmetricKey = rsa.Decrypt(encryptedSymmetricKey, RSAEncryptionPadding.Pkcs1);
            var des          = DES.Create();
            des.Key = symmetricKey;
            SetDes(des);

            Console.WriteLine("Key exchange successful");
        }

        public async Task SendMessages(IAsyncEnumerable<byte[]> messageStream) {
            var des = GetDes();
            try {
                await foreach (var encryptedMessage in messageStream.Skip(1)) {
                    var messageBytes = des.DecryptEcb(encryptedMessage, PaddingMode.None);
                    var message      = Encoding.Default.GetString(messageBytes);
                    Console.Write("\nMessage received: ");
                    Console.WriteLine(message);
                    Console.Write("Input message: ");
                }
            } catch (Exception) {
                // ignored
            }

            Console.WriteLine($"\nClient {Context.ConnectionId} disconnected, press ENTER to wait for new connections");
        }

        public async IAsyncEnumerable<byte[]> ReceiveMessages([EnumeratorCancellation] CancellationToken cancellationToken) {
            await using var inputStream = Console.OpenStandardInput();
            using var       reader      = new StreamReader(inputStream);
            var             des         = GetDes();
            while (!cancellationToken.IsCancellationRequested) {
                Console.Write("Input message: ");
                var message          = (await reader.ReadLineAsync())!;
                var encryptedMessage = des.EncryptEcb(Encoding.Default.GetBytes(message), PaddingMode.Zeros);
                yield return encryptedMessage;
            }
        }

        public Task SendMessage(byte[] encryptedMessage) {
            var des          = GetDes();
            var messageBytes = des.DecryptEcb(encryptedMessage, PaddingMode.None);
            var message      = Encoding.Default.GetString(messageBytes);
            Console.Write("\nMessage received: ");
            Console.WriteLine(message);
            Console.Write("Input message: ");
            return Task.CompletedTask;
        }

        public override Task OnDisconnectedAsync(Exception? exception) {
            try {
                var rsa = GetRsa();
                rsa.Dispose();
            } catch (Exception) {
                // ignored
            }

            try {
                var des = GetDes();
                des.Dispose();
            } catch (Exception) {
                // ignored
            }

            return Task.CompletedTask;
        }

        private RSA GetRsa() {
            return (RSA)Context.Items["RSA"]!;
        }

        private void SetRsa(RSA rsa) {
            Context.Items["RSA"] = rsa;
        }

        private DES GetDes() {
            return (DES)Context.Items["DES"]!;
        }

        private void SetDes(DES des) {
            Context.Items["DES"] = des;
        }
    }
}
