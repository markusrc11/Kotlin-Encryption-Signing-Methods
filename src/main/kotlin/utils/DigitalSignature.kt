package utils

import java.nio.file.Files
import java.nio.file.Paths
import java.security.Signature

class DigitalSignature {
    fun sign(msg: String) {
        val signature = initSignature()
        val signUpdated = signMsg(msg.toByteArray(), signature)
        Files.write(Paths.get("digital_signature_2"), signUpdated)
        println("isCorrect: ${verifySignature(signUpdated!!, msg.toByteArray())}")
    }

    private fun initSignature(): Signature {
        val signature: Signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(Keys.getPrivateKey())
        return signature
    }

    private fun signMsg(msgToEncrypt: ByteArray, signature: Signature): ByteArray? {
        signature.update(msgToEncrypt)
        return signature.sign()
    }

    private fun verifySignature(encryptedMsgBytes: ByteArray, msg: ByteArray): Boolean {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(Keys.getPublicKey())

        signature.update(encryptedMsgBytes)
        return signature.verify(msg)
    }
}