package com.example.c001apk.compose.ui.base

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.c001apk.compose.constant.Constants
import com.example.c001apk.compose.logic.repository.UserPreferencesRepository
import com.example.c001apk.compose.util.CookieUtil.szlmId
import com.example.c001apk.compose.util.TokenDeviceUtils.buildDeviceCode
import com.example.c001apk.compose.util.TokenDeviceUtils.randHexString
import kotlinx.coroutines.launch

/**
 * Created by bggRGjQaUbCoE on 2024/6/15
 */
open class PrefsViewModel(
    private val userPreferencesRepository: UserPreferencesRepository
) : ViewModel() {

    fun regenerateParams() {
        viewModelScope.launch { regenerateParamsNow(szlmId) }
    }

    suspend fun regenerateParamsNow(existingSzlmId: String = szlmId) {
        val manufacturer = android.os.Build.MANUFACTURER.orEmpty().ifBlank { "OnePlus" }
        val brand = android.os.Build.BRAND.orEmpty().ifBlank { manufacturer }
        val model = android.os.Build.MODEL.orEmpty().ifBlank { "PJZ110" }
        val buildNumber = android.os.Build.DISPLAY.orEmpty().ifBlank { "PJZ110_16.0.5.703(CN01)" }
        val sdkInt = android.os.Build.VERSION.SDK_INT.toString()
        val androidVersion = android.os.Build.VERSION.RELEASE.orEmpty().ifBlank { "16" }
        val effectiveSzlmId = existingSzlmId.ifBlank { randHexString(16) }
        val userAgent =
            "Dalvik/2.1.0 (Linux; U; Android $androidVersion; $model $buildNumber) (#Build; $brand; $model; $buildNumber; $androidVersion) +CoolMarket/${Constants.VERSION_NAME}-${Constants.VERSION_CODE}-${Constants.MODE}"
        val xAppDevice = buildDeviceCode(
            effectiveSzlmId, manufacturer, brand, model, buildNumber
        )

        userPreferencesRepository.apply {
            if (existingSzlmId.isBlank()) setSzlmId(effectiveSzlmId)
            setVersionName(Constants.VERSION_NAME)
            setVersionCode(Constants.VERSION_CODE)
            setApiVersion(Constants.API_VERSION)
            setManufacturer(manufacturer)
            setBrand(brand)
            setModel(model)
            setBuildNumber(buildNumber)
            setSdkInt(sdkInt)
            setAndroidVersion(androidVersion)
            setUserAgent(userAgent)
            setXAppDevice(xAppDevice)
        }
    }
}
