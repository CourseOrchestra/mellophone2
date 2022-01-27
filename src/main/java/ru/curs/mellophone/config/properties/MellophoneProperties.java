package ru.curs.mellophone.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(MellophoneProperties.PREFIX)
public class MellophoneProperties {
    public static final String PREFIX = "mellophone";

    private String configFile;

    public String getConfigFile() {
        return configFile;
    }

    public void setConfigFile(String configFile) {
        this.configFile = configFile;
    }

}
