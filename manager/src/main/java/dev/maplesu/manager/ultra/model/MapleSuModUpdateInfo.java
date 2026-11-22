package dev.maplesu.manager.ultra.model;

public class MapleSuModUpdateInfo {
    private boolean hasNewVersion;
    private String latestVer;
    private String downloadUrl;
    private String changelogUrl;

    public MapleSuModUpdateInfo(boolean hasNewVersion,
                            String latestVer,
                            String downloadUrl,
                            String changelogUrl) {
        this.hasNewVersion = hasNewVersion;
        this.latestVer = latestVer;
        this.downloadUrl = downloadUrl;
        this.changelogUrl = changelogUrl;
    }

    public boolean isHasNewVersion() {
        return hasNewVersion;
    }

    public void setHasNewVersion(boolean hasNewVersion) {
        this.hasNewVersion = hasNewVersion;
    }

    public String getLatestVer() {
        return latestVer;
    }

    public void setLatestVer(String latestVer) {
        this.latestVer = latestVer;
    }

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public void setDownloadUrl(String downloadUrl) {
        this.downloadUrl = downloadUrl;
    }

    public String getChangelogUrl() {
        return changelogUrl;
    }

    public void setChangelogUrl(String changelogUrl) {
        this.changelogUrl = changelogUrl;
    }
}
