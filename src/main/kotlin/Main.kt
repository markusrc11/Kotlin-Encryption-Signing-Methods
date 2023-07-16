import utils.DigitalSignature
import utils.GPGMethod
import utils.ManualEncryption


const val filePath = "Path to file"
const val msg = "Hey, how are you?"

fun main() {
    val text = "Hey, how are you?"

    val gpg = GPGMethod()
    val msg = gpg.encryptAndSign(text)
    val decryptedMsg = gpg.decryptAndVerify(msg)


    // More info: https://www.baeldung.com/java-digital-signature
    ManualEncryption().encrypt(text)

    DigitalSignature().sign(text)
}



