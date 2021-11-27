using System.Threading.Tasks;

namespace SecureChat.Hubs {
    public interface IChatClient {
        Task SendPublicKey(byte[] publicKey);
    }
}
