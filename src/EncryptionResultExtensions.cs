namespace LogicSoftware.WebPushEncryption
{
    public static class EncryptionResultExtensions
    {
        public static string Base64EncodePublicKey(this EncryptionResult source)
        {
            return WebEncoder.Base64UrlEncode(source.PublicKey);
        }

        public static string Base64EncodeSalt(this EncryptionResult source)
        {
            return WebEncoder.Base64UrlEncode(source.Salt);
        }
    }
}
