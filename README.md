# Web Push Encryption
Chrome/Mozilla push notifications payload encryption for .NET

# Installation

LogicSoftware.WebPushEncryption can be installed via the nuget UI (as WebPushEncryption), or via the nuget package manager console:

    PM> Install-Package WebPushEncryption

# Usage 

    var encryptedPayload = LogicSoftware.WebPushEncryption.Encryptor.Encrypt(p256dh, auth, payload);

    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, pushEndpoint);

    // send encrypted payload instead of original
    request.Content = new ByteArrayContent(encryptedPayload.Payload);
    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
    request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;

    // append public key and salt as headers
    request.Content.Headers.ContentEncoding.Add("aesgcm");
    request.Headers.Add("Crypto-Key", "keyid=p256dh;dh=" + encryptedPayload.Base64EncodePublicKey());
    request.Headers.Add("Encryption", "keyid=p256dh;salt=" + encryptedPayload.Base64EncodeSalt());
