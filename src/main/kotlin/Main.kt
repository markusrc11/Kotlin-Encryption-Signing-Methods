import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.protection.SecretKeyRingProtector
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import java.util.*
import javax.crypto.Cipher


const val password = "123456"
const val filePath = "Path to file"
const val msg = "Hey, how are you?"

fun main() {
    println("Hello World!")

    // More info: https://github.com/pgpainless/pgpainless
    GPGMethod()
}

fun GPGMethod() {
// Prepare keys
    // Required by the sender
    // Prepare keys

    // FROM FILE
    val receivedSignature = File("~/pubkey.asc").inputStream()
    val pubKey: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(receivedSignature)

    // FROM STRING
    val keyAlice: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing("ALICE_KEY")
    val certificateBob: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing("BOB_CERT")
    val protectorAlice = SecretKeyRingProtector.unprotectedKeys()

    // Required by the recipient
    val keyBob: PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing("BOB_KEY")
    val certificateAlice: PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing("ALICE_CERT")
    val protectorBob = SecretKeyRingProtector.unprotectedKeys()

    GPGEncryptAndSign(certificateBob, certificateAlice, protectorAlice, keyAlice)


    // plaintext message to encrypt
    val fis = File("/home/markusrc11/doc.sig").inputStream()

    GPGDecryptAndVerify(fis, pubKey)

}

private fun GPGDecryptAndVerify(fis: FileInputStream, pubKey: PGPPublicKeyRing): ByteArrayOutputStream {
    // Decrypt and verify signatures
    val decryptor = PGPainless.decryptAndOrVerify()
        .onInputStream(fis)
        .withOptions(
            ConsumerOptions()
//                .addDecryptionKey(keyBob, protectorBob)
                .addVerificationCert(pubKey)
        )

    val plaintext = ByteArrayOutputStream()

    Streams.pipeAll(decryptor, plaintext)
    decryptor.close()
    return plaintext
}

private fun GPGEncryptAndSign(
    certificateBob: PGPPublicKeyRing,
    certificateAlice: PGPPublicKeyRing,
    protectorAlice: SecretKeyRingProtector?,
    keyAlice: PGPSecretKeyRing
): String {
    // plaintext message to encrypt
    val message = "Hello, World!\n"
    val ciphertext = ByteArrayOutputStream()
    // Encrypt and sign
    // Encrypt and sign
    val encryptor = PGPainless.encryptAndOrSign()
        .onOutputStream(ciphertext)
        .withOptions(
            ProducerOptions.signAndEncrypt( // we want to encrypt communication (affects key selection based on key flags)
                EncryptionOptions.encryptCommunications()
                    .addRecipient(certificateBob)
                    .addRecipient(certificateAlice),
                SigningOptions()
                    .addInlineSignature(protectorAlice, keyAlice, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
            ).setAsciiArmor(true)
        )

    // Pipe data trough and CLOSE the stream (important)
    Streams.pipeAll(ByteArrayInputStream(message.toByteArray(StandardCharsets.UTF_8)), encryptor)
    encryptor.close()

    // Encrypted message
    val encryptedMessage = ciphertext.toString()
    return encryptedMessage
}

private fun isCorrect(decryptedMessageHash: ByteArray, newMessageHash: ByteArray): Boolean {
    return decryptedMessageHash.contentEquals(newMessageHash)
}
private fun decrypt(encryptedMessageHash: ByteArray?): ByteArray? {
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.DECRYPT_MODE, getPublicKey())
    val decryptedMessageHash = cipher.doFinal(encryptedMessageHash)
    return decryptedMessageHash
}

private fun verifySignature(): ByteArray {
    val encryptedMessageHash = Files.readAllBytes(Paths.get("digital_signature_1"))
    return encryptedMessageHash
}

private fun saveSignature() {
    Files.write(Paths.get("digital_signature_1"), encrypt());
}
private fun encrypt(): ByteArray {
    val cipher: Cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey())
    val digitalSignature: ByteArray = cipher.doFinal(generateMsgHash(msg.toByteArray()))
    return digitalSignature
}
private fun generateMsgHash(messageBytes: ByteArray): ByteArray? {
    val md = MessageDigest.getInstance("SHA-256")
    val messageHash = md.digest(messageBytes)
    return messageHash
}
private fun getPublicKey(): PublicKey? {
    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(FileInputStream("receiver_keytore.p12"), password.toCharArray())
    val certificate: Certificate = keyStore.getCertificate("receiverKeyPair")
    return certificate.publicKey
}
private fun getPrivateKey(): PrivateKey {
    val keyStore = KeyStore.getInstance("PKCS12")
    keyStore.load(FileInputStream("sender_keystore.p12"), password.toCharArray())
    return keyStore.getKey("senderKeyPair", password.toCharArray()) as PrivateKey
}