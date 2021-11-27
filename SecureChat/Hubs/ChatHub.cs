using System;
using System.Security.Cryptography;
using System.Text;
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

            Task.Run(async () => {
                while (true) {
                    Console.Write("Input message: ");
                    var message          = Console.ReadLine()!;
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

            return Task.CompletedTask;
        }

        private RSA GetRsa() {
            return Context.Items["RSA"] as RSA ?? throw new Exception();
        }

        private DES GetDes() {
            return Context.Items["DES"] as DES ?? throw new Exception();
        }

        private void SetRsa(RSA rsa) {
            Context.Items["RSA"] = rsa;
        }

        private void SetDes(DES des) {
            Context.Items["DES"] = des;
        }
    }
}
