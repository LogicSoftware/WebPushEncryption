﻿namespace LogicSoftware.WebPushEncryption
{
    public class EncryptionResult
    {
        public byte[] PublicKey { get; set; }
        public byte[] Payload { get; set; }
        public byte[] Salt { get; set; }
    }
}
