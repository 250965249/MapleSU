package dev.maplesu.manager.t3

import android.content.Context

internal class T3AndroidAccountStore(context: Context) : T3AccountStore {
    private val preferences = context.applicationContext
        .getSharedPreferences("maplesu_t3_account", Context.MODE_PRIVATE)

    override fun read(): T3Session? {
        val identity = readIdentity() ?: return null
        val statecode = preferences.getString("statecode", null)?.takeIf(String::isNotBlank) ?: return null
        return T3Session(identity.account, identity.identity, statecode)
    }

    override fun readIdentity(): T3AccountIdentity? {
        val account = preferences.getString("account", null)?.takeIf(String::isNotBlank) ?: return null
        val identity = preferences.getString("identity", null)?.takeIf(String::isNotBlank) ?: return null
        return T3AccountIdentity(account, identity)
    }

    override fun writeIdentity(identity: T3AccountIdentity) {
        preferences.edit()
            .putString("account", identity.account)
            .putString("identity", identity.identity)
            .remove("statecode")
            .apply()
    }

    override fun write(session: T3Session) {
        preferences.edit()
            .putString("account", session.account)
            .putString("identity", session.identity)
            .putString("statecode", session.statecode)
            .apply()
    }

    override fun readNotice(): String? = preferences.getString("notice", null)?.takeIf(String::isNotBlank)

    override fun writeNotice(notice: String) {
        preferences.edit().putString("notice", notice).apply()
    }
}
