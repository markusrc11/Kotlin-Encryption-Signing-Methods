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