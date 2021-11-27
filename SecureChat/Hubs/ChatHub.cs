using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.SignalR;

namespace SecureChat.Hubs {
    public class ChatHub : Hub<IChatClient> {
        private readonly IHubContext<ChatHub, IChatClient> _context;

        public ChatHub(IHubContext<ChatHub, IChatClient> context) {
            _context = context;
        }

        public override async Task OnConnectedAsync() {
            var rsa = RSA.Create();
            SetRsa(rsa);
            var publicKey = rsa.ExportRSAPublicKey();

            Console.WriteLine("Sending RSA public key");
            await Clients.Caller.SendPublicKey(publicKey);
        }

        public void SendSymmetricKey(byte[] encryptedSymmetricKey) {
            var connectionId = Context.ConnectionId;
            var rsa          = GetRsa();
            var symmetricKey = rsa.Decrypt(encryptedSymmetricKey, RSAEncryptionPadding.Pkcs1);
            var des          = DES.Create();
            des.Key = symmetricKey;
            SetDes(des);

            Console.WriteLine("Key exchange successful");

            var tokenSource = new CancellationTokenSource();
            SetTokenSource(tokenSource);

            Task.Run(async () => {
                while (!tokenSource.IsCancellationRequested) {
                    Console.Write("Input message: ");
                    var message = Console.ReadLine()!;
                    var encryptedMessage = des.EncryptEcb(Encoding.Default.GetBytes(message), PaddingMode.Zeros);
                    await _context.Clients.Client(connectionId).SendMessage(encryptedMessage);
                }
            });
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

            try {
                var tokenSource = GetTokenSource();
                tokenSource.Cancel();
                tokenSource.Dispose();
            } catch (Exception) {
                // ignored
            }

            Console.WriteLine($"\nClient {Context.ConnectionId} disconnected, press ENTER to wait for new connections");

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

        private void SetTokenSource(CancellationTokenSource tokenSource) {
            Context.Items["tokenSource"] = tokenSource;
        }

        private CancellationTokenSource GetTokenSource() {
            return (CancellationTokenSource)Context.Items["tokenSource"]!;
        }
    }
}
