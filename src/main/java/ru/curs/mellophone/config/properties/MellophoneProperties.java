package ru.curs.mellophone.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(MellophoneProperties.PREFIX)
public class MellophoneProperties {
    public static final String PREFIX = "mellophone";

    private String mellophoneConfigPath;
    private String log4jConfigPath;

    public String getMellophoneConfigPath() {
        return mellophoneConfigPath;
    }

    public void setMellophoneConfigPath(String mellophoneConfigPath) {
        this.mellophoneConfigPath = mellophoneConfigPath;
    }

    public String getLog4jConfigPath() {
        return log4jConfigPath;
    }

    public void setLog4jConfigPath(String log4jConfigPath) {
        this.log4jConfigPath = log4jConfigPath;
    }
}
