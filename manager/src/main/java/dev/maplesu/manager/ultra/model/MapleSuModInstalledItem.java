package dev.maplesu.manager.ultra.model;



import android.text.TextUtils;



public class MapleSuModInstalledItem {

    private String name;

    private String desc;

    private String ver;

    private String id32;

    private String author;

    private String updateJson;

    private String miniSdk;

    private boolean webUi;

    private MapleSuModRunState runState;

    private Boolean enabled;
    private boolean enableToggleSupported;
    private boolean needsReboot;

    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean value) { enabled = value; }
    public boolean isEnableToggleSupported() { return enableToggleSupported; }
    public void setEnableToggleSupported(boolean value) { enableToggleSupported = value; }
    public boolean isNeedsReboot() { return needsReboot; }
    public void setNeedsReboot(boolean value) { needsReboot = value; }




    private MapleSuModUpdateInfo updateInfo;



    public MapleSuModInstalledItem(String name,

                               String desc,

                               String ver,

                               String id32,

                               String author,

                               String updateJson,

                               String miniSdk,

                               boolean webUi,

                               MapleSuModRunState runState) {

        this.name = name;

        this.desc = desc;

        this.ver = ver;

        this.id32 = id32;

        this.author = author;

        this.updateJson = updateJson;

        this.miniSdk = miniSdk;

        this.webUi = webUi;

        this.runState = runState == null ? MapleSuModRunState.NOT_RUNNING : runState;

        this.updateInfo = null;

    }



    public String getName() {

        return name;

    }



    public void setName(String name) {

        this.name = name;

    }



    public String getDesc() {

        return desc;

    }



    public void setDesc(String desc) {

        this.desc = desc;

    }



    public String getVer() {

        return ver;

    }



    public void setVer(String ver) {

        this.ver = ver;

    }



    public String getId32() {

        return id32;

    }



    public void setId32(String id32) {

        this.id32 = id32;

    }



    public String getAuthor() {

        return author;

    }



    public void setAuthor(String author) {

        this.author = author;

    }



    public String getUpdateJson() {

        return updateJson;

    }



    public void setUpdateJson(String updateJson) {

        this.updateJson = updateJson;

    }



    public String getMiniSdk() {

        return miniSdk;

    }



    public void setMiniSdk(String miniSdk) {

        this.miniSdk = miniSdk;

    }



    public boolean isWebUi() {

        return webUi;

    }



    public void setWebUi(boolean webUi) {

        this.webUi = webUi;

    }



    public MapleSuModRunState getRunState() {

        return runState;

    }



    public void setRunState(MapleSuModRunState runState) {

        this.runState = runState;

    }



    public MapleSuModUpdateInfo getUpdateInfo() {

        return updateInfo;

    }



    public void setUpdateInfo(MapleSuModUpdateInfo updateInfo) {

        this.updateInfo = updateInfo;

    }



    public boolean hasChangelog() {

        return updateInfo != null && !TextUtils.isEmpty(updateInfo.getChangelogUrl());

    }

}