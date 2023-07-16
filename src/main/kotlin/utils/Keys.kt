package utils

import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate

object Keys {
    val password = "123456"

    fun getPublicKey(): PublicKey? {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(FileInputStream("receiver_keytore.p12"), password.toCharArray())
        val certificate: Certificate = keyStore.getCertificate("receiverKeyPair")
        return certificate.publicKey
    }
    fun getPrivateKey(): PrivateKey {
        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(FileInputStream("sender_keystore.p12"), password.toCharArray())
        return keyStore.getKey("senderKeyPair", password.toCharArray()) as PrivateKey
    }
}