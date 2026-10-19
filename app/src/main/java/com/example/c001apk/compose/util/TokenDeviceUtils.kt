package com.example.c001apk.compose.util

import android.util.Base64
import com.example.c001apk.compose.constant.Constants
import com.example.c001apk.compose.constant.Constants.EMPTY_STRING
import com.example.c001apk.compose.util.Utils.getBase64
import com.example.c001apk.compose.util.Utils.getMD5
import org.mindrot.jbcrypt.BCrypt
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom


object TokenDeviceUtils {
    private val secureRandom = SecureRandom()

    fun encode(deviceInfo: String): String {
        val charset: Charset = StandardCharsets.UTF_8
        val bytes = deviceInfo.toByteArray(charset)
        val encodeToString = Base64.encodeToString(bytes, 0)
        val replace = StringBuilder(encodeToString).reverse().toString()
        return Regex("\\r\\n|\\r|\\n|=").replace(replace, EMPTY_STRING)
    }

    /** Keep the server-recognized device-code structure and replace only its identity/model fields. */
    fun buildDeviceCode(
        szlmId: String,
        manufacturer: String,
        brand: String,
        model: String,
        buildNumber: String,
    ): String {
        val encoded = Constants.DEFAULT_DEVICE_CODE
        val reversed = encoded.reversed()
        val padding = (4 - reversed.length % 4) % 4
        val decoded = String(
            Base64.decode(reversed + "=".repeat(padding), Base64.DEFAULT),
            StandardCharsets.UTF_8
        )
        val parts = decoded.split(";").toMutableList()
        if (parts.size < 8) return encoded
        parts[0] = szlmId
        parts[4] = " $manufacturer"
        parts[5] = " $brand"
        parts[6] = " $model"
        parts[7] = " $buildNumber"
        return encode(parts.joinToString(";"))
    }

    fun randHexString(@Suppress("SameParameterValue") n: Int): String {
        return buildString(n * 2) {
            repeat(n) {
                val value = secureRandom.nextInt(256)
                append(HEX_CHARS[value ushr 4])
                append(HEX_CHARS[value and 0x0f])
            }
        }.uppercase()
    }

    fun String.getTokenV2(): String {
        val timeStamp = (System.currentTimeMillis() / 1000f).toString()

        val base64TimeStamp = timeStamp.getBase64()
        val md5TimeStamp = timeStamp.getMD5()
        val md5DeviceCode = this.getMD5()

        val token = "${Constants.APP_LABEL}?$md5TimeStamp$$md5DeviceCode&${Constants.APP_ID}"
        val base64Token = token.getBase64()
        val md5Base64Token = base64Token.getMD5()
        val md5Token = token.getMD5()

        val bcryptSalt = "${"$2a$10$$base64TimeStamp/$md5Token".substring(0, 31)}u"
        val bcryptResult = BCrypt.hashpw(md5Base64Token, bcryptSalt)

        return "v2${bcryptResult.replaceRange(0, 3, "$2y").getBase64()}"
    }


    fun String.getTokenV3(
        versionCode: String,
        timestamp: Long = System.currentTimeMillis() / 1000L
    ): String {
        val vc = versionCode.toLongOrNull() ?: Constants.VERSION_CODE.toLong()
        val off = (4 * ((timestamp + vc) % 100) + 128).toInt()

        val b2 = Base64.decode(KEY, off, 128, Base64.NO_WRAP)
        val s = Constants.APP_ID.toByteArray()
            .plus("&".toByteArray())
            .plus(b2)
            .plus("&".toByteArray())
            .plus(toByteArray().md5Hex().toByteArray())
            .plus("&".toByteArray())
            .plus(timestamp.toString().toByteArray())
            .plus("&".toByteArray())
            .plus(vc.toString().toByteArray())

        val salt = Base64.encodeToString(
            "${timestamp.toString(16)}/${s.md5Hex()}".toByteArray(),
            Base64.NO_WRAP
        ).substring(0, 22)
        // jBCrypt emits $2a hashes; changing the prefix preserves the same hash bytes.
        val hash = "\$2y" + BCrypt.hashpw(
            Base64.encodeToString(s, Base64.NO_WRAP).toByteArray().md5Hex(),
            "\$2a\$04\$$salt"
        ).substring(3)

        return "v3" + Base64.encodeToString(hash.toByteArray(), Base64.NO_WRAP)
    }

    private fun ByteArray.md5Hex(): String {
        val digest = MessageDigest.getInstance("MD5").digest(this)
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            val v = b.toInt() and 0xff
            sb.append(HEX_CHARS[v ushr 4]).append(HEX_CHARS[v and 0x0f])
        }
        return sb.toString()
    }

    private const val HEX_CHARS = "0123456789abcdef"
    /** Base64 encoded key table used by the v3 token algorithm. */
    private const val KEY_B64 =
        "VFRCVU9GUXNRMEVsTFVNa1dERWpRU0VzVXlFbUxETkFVeTFEUEZZdUl5MGlNVU01SXpCVUpGY3RNeWtoTVVRMUpTMURPU1V4TXpoUUxWTXdWMDBzSXloU01UUXNXVEZEUkZFd1EwUlZNU1FrVVMwaktTTXR" +
        "KRGhZTFZRa1VqRXpLU1FzTTBCVkxUUXdVaTAwTlNNc00yQlhMVk1sSkMxRE5GbE5MQ1EwV1RFekxTUXhRMEVoTEVNbElqRXpLRmN3TXowbExpTkVWekVqUFNZdU5Ea2tMRk13Vml4VEtGa3RRemhYTEZNc1" +
        "dDNGpMU1l0VTJCVFRUQTBMRkV1TXpoVExqTWhJakZETUZNc0kwQlZMQ1FrVUN3ekpTSXNJekJTTUVNOFVDeEVMU0l0STJCUUxVUW9VeTBqTEZNc0l5VWtNRlF3VmswdFJDeFlNVE1sSkM0ME5TRXdVMFJRT" +
        "EZNaElpMGtOU013VTJCUUxqTmdVeXdqT0ZFc05DeFRMRU13V0N4VUxTRXRJeVJUTEROQkl5MDBKRlpOTVVNc1VEQkVKRmd0TkMwa0xEUWtXQzFETUZNeFJDa2pMVk0wVml4VE1GZ3hJeTBtTFZNeEpTMHpK" +
        "RlF4TTJCUUxTUTRXVEJETUZNdUkwVWhUU3d6UEZndFJEQlJNRE5FVVMwak9GWXVKRGtsTVNRMFV6QXpOU013UkRra01UTWtWU3hVTUZRdFJDeFlNVE5GSXl4RUxGWXNJelVoTGlRMFYwMHhOQ3hWTENNMFZ" +
        "5NHpKRlV4TkN4VExGUTRWeTRqWUZZeEpEVWpMVU13VXpGRFBGSXNNMEVsTERNc1ZEQTBPU011TkNrbUxFUWtWaXhFTVNKTkxUTW9VaXd6TEZjdFUwUlFMaVF3VlRGREpTVXdVeWtqTVVNaEl5MHpJU1VzST" +
        "BFak1UTXdVUzFVTkZjeFJERWxMVVF0SlM0a05GSXNJemhaVFRCVFlGRXdReVJZTFNNbElTNDBMRmdzVkRSWkxVUW9XVEJEUUZZdFJDeFdMak5FVkRCRE1Ga3RORFVsTEZRNFZTMVVKRmd3TXpSV0xEUTRVV" +
        "TB3UXkwbUxVUTRXUzFUTVNNc1V5VWlNVU5BVVN4VUxGWXVJMFJVTGlNc1dERkVMRk14STJCUUxWTTBXUzRrT0Zjd00wUlhMVk1vV0MwaktGRXhMQ00wVml4VE5GQXRSRFJXTFVRbEpDMVRKRkF3TkN4Z1lB"

    private val KEY: ByteArray by lazy { Base64.decode(KEY_B64, Base64.NO_WRAP) }
}
