package utils

import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import javax.crypto.Cipher

class ManualEncryption {

    fun encrypt(msg: String) {
        val hashMsg = generateMsgHash(msg.toByteArray())
        val encryptedMsg = encrypt(hashMsg!!)
        saveSignature(encryptedMsg)
        val decryptedMsg = decrypt(encryptedMsg)
        println("isCorrect: ${isCorrect(decryptedMsg!!, generateMsgHash(msg.toByteArray())!!)}")
    }

    private fun isCorrect(decryptedMessageHash: ByteArray, newMessageHash: ByteArray): Boolean {
        return decryptedMessageHash.contentEquals(newMessageHash)
    }
    private fun decrypt(encryptedMessageHash: ByteArray?): ByteArray? {
        val cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.DECRYPT_MODE, Keys.getPublicKey())
        return cipher.doFinal(encryptedMessageHash)
    }

    private fun saveSignature(encryptedMsg: ByteArray) {
        Files.write(Paths.get("digital_signature_1"), encryptedMsg);
    }
    private fun encrypt(hashMsg: ByteArray): ByteArray {
        val cipher: Cipher = Cipher.getInstance("RSA")
        cipher.init(Cipher.ENCRYPT_MODE, Keys.getPrivateKey())
        return cipher.doFinal(hashMsg)
    }
    private fun generateMsgHash(messageBytes: ByteArray): ByteArray? {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(messageBytes)
    }
}