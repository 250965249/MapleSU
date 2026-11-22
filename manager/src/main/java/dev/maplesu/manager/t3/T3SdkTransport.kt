package dev.maplesu.manager.t3

import t3sdk.T3Verify

/** Routes manager account operations through the retained official T3 SDK. */
internal class T3SdkTransport(
    private val sdk: T3Verify = T3Verify(),
) : T3Transport {
    init {
        sdk.initPlain("9E7ED731C40B8EFE")
        sdk.setRegisterCode("7DB96ED993B8F15C")
        sdk.setUserLoginCode("6BB1C459D63AE8FC")
        sdk.setUserHeartbeatCode("8007E66F777EE16F")
        sdk.setModifyCoreCode("A4EE92F2C6743A91")
    }

    override fun call(operation: T3Operation, parameters: Map<String, String>): T3Response {
        fun parameter(name: String) = parameters.getValue(name)
        val result = when (operation) {
            T3Operation.REGISTER -> sdk.userRegister(parameter("user"), parameter("pass"), parameter("email"))
            T3Operation.LOGIN -> sdk.userLogin(parameter("user"), parameter("pass"), parameter("imei"))
            T3Operation.HEARTBEAT -> sdk.userHeartbeat(parameter("user"), parameter("pass"), parameter("statecode"))
            T3Operation.UPDATE_CORE -> sdk.modifyCoreByUser(parameter("user"), parameter("pass"), parameter("core"))
            T3Operation.NOTICE -> sdk.getNotice()
        }
        if (!result.success) return T3Response(201, result.error.orEmpty())
        val message = if (result is T3Verify.T3NoticeResult) result.notice.orEmpty() else result.msg.orEmpty()
        return T3Response(200, message, (result as? T3Verify.T3LoginResult)?.statecode)
    }
}
